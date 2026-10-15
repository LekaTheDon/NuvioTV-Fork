package com.nuvio.tv.data.simkl

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SimklAuthRepository(
    private val apiClient: SimklApiClient,
    private val configuration: SimklApiConfiguration,
    private val storage: SimklAuthStorage,
    private val nowEpochMs: () -> Long = System::currentTimeMillis
) {
    @Inject
    constructor(
        apiClient: SimklApiClient,
        configuration: SimklApiConfiguration,
        storage: SimklAuthStorage
    ) : this(apiClient, configuration, storage, System::currentTimeMillis)

    private val mutex = Mutex()
    private val json = Json { ignoreUnknownKeys = true }

    val state: StateFlow<SimklAuthState> = storage.state

    fun hasRequiredCredentials(): Boolean = configuration.clientId.isNotBlank()

    suspend fun startPinAuth(): SimklPinSession = mutex.withLock {
        val authScope = storage.currentScope()
        if (!hasRequiredCredentials()) throw SimklAuthException(SimklAuthError.MISSING_CLIENT_ID)
        // FEL fork: apps registered on Simkl's newer OAuth 2.0 system are refused by /oauth/pin
        // ("unauthorized_client") and must use the standard device flow instead.
        val response = try {
            executeAuthRequest(SimklApiRequest(SimklHttpMethod.GET, "/oauth/pin", requiresAuthentication = false))
        } catch (error: SimklAuthException) {
            if (error.simklErrorCode() != "unauthorized_client") throw error
            executeAuthRequest(
                SimklApiRequest(
                    method = SimklHttpMethod.POST,
                    path = "/oauth2/device",
                    body = buildJsonObject { put("client_id", configuration.clientId) }.toString(),
                    requiresAuthentication = false,
                    retryPolicy = SimklRetryPolicy.NEVER
                )
            )
        }
        val payload = decodePinResponse(response.body)
        val deviceCode = payload.deviceCode?.trim()?.takeIf(String::isNotBlank)
        val userCode = payload.userCode?.trim()?.takeIf(String::isNotBlank)
        val verificationUri = (payload.verificationUri ?: payload.verificationUrl)
            ?.trim()
            ?.takeIf(String::isNotBlank)
        val expiresIn = payload.expiresIn?.takeIf { it > 0L }
        val interval = payload.interval?.coerceAtLeast(1)
        if ((payload.result != "OK" && deviceCode == null) || userCode == null || verificationUri == null || expiresIn == null || interval == null) {
            throw SimklAuthException(SimklAuthError.INVALID_PIN_RESPONSE)
        }
        val session = SimklPinSession(
            userCode = userCode,
            verificationUri = verificationUri,
            expiresAtEpochMs = nowEpochMs() + expiresIn * 1_000L,
            intervalSeconds = interval,
            deviceCode = deviceCode
        )
        if (!storage.savePinSession(session, authScope)) {
            throw SimklAuthException(SimklAuthError.PIN_INVALIDATED)
        }
        session
    }

    suspend fun pollPin(): SimklPinPollResult = mutex.withLock {
        val authScope = storage.currentScope()
        val session = storage.state.value.pinSession ?: return@withLock SimklPinPollResult.Invalidated
        if (nowEpochMs() >= session.expiresAtEpochMs) {
            storage.clearPinSession(SimklAuthError.PIN_EXPIRED, authScope)
            return@withLock SimklPinPollResult.Expired
        }
        session.deviceCode?.let { deviceCode ->
            return@withLock pollDeviceToken(deviceCode, authScope)
        }
        if (!PIN_PATTERN.matches(session.userCode)) {
            storage.clearPinSession(SimklAuthError.PIN_INVALIDATED, authScope)
            return@withLock SimklPinPollResult.Invalidated
        }
        val response = executeAuthRequest(
            SimklApiRequest(
                method = SimklHttpMethod.GET,
                path = "/oauth/pin/${session.userCode}",
                requiresAuthentication = false
            )
        )
        val payload = decodePinResponse(response.body)
        if (!payload.deviceCode.isNullOrBlank()) {
            storage.clearPinSession(SimklAuthError.PIN_INVALIDATED, authScope)
            return@withLock SimklPinPollResult.Invalidated
        }
        val token = payload.accessToken?.trim()?.takeIf(String::isNotBlank)
        if (payload.result == "OK" && token != null) {
            if (!storage.completePinAuthorization(token, authScope)) {
                return@withLock SimklPinPollResult.Invalidated
            }
            try {
                refreshUserSettings(scope = authScope)
            } catch (error: CancellationException) {
                throw error
            } catch (_: Throwable) {
                Unit
            }
            return@withLock SimklPinPollResult.Authorized
        }
        if (payload.result == "KO") return@withLock SimklPinPollResult.Pending
        throw SimklAuthException(SimklAuthError.INVALID_PIN_RESPONSE)
    }

    suspend fun refreshUserSettings(
        activityWatermark: String? = null,
        scope: SimklAuthScope = storage.currentScope()
    ): String? {
        if (!storage.isCurrent(scope) || !storage.state.value.isAuthenticated) return null
        val response = apiClient.execute(
            request = SimklApiRequest(SimklHttpMethod.POST, "/users/settings"),
            expectedAuthScope = scope
        )
        val settings = runCatching { json.decodeFromString<SimklUserSettingsResponse>(response.body) }.getOrNull()
            ?: return null
        val username = settings.user?.name?.trim()?.takeIf(String::isNotBlank)
        val saved = storage.saveIdentity(
            username = username,
            accountId = settings.account?.id,
            settingsActivityWatermark = activityWatermark,
            scope = scope
        )
        return username.takeIf { saved }
    }

    suspend fun synchronizeUserSettings(activityWatermark: String?) {
        val authScope = storage.currentScope()
        if (!storage.state.value.isAuthenticated) return
        try {
            when (simklSettingsRefreshAction(storage.state.value, activityWatermark)) {
                SimklSettingsRefreshAction.NONE -> Unit
                SimklSettingsRefreshAction.RECORD_WATERMARK -> {
                    storage.recordSettingsActivityWatermark(requireNotNull(activityWatermark), authScope)
                }
                SimklSettingsRefreshAction.FETCH -> refreshUserSettings(activityWatermark, authScope)
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Throwable) {
            Unit
        }
    }

    fun cancelPinAuth() = storage.clearPinSession()

    fun disconnect() = storage.clearAuth()

    private suspend fun executeAuthRequest(request: SimklApiRequest): SimklApiResponse = try {
        apiClient.execute(request)
    } catch (error: CancellationException) {
        throw error
    } catch (error: SimklAuthException) {
        throw error
    } catch (error: Throwable) {
        throw SimklAuthException(SimklAuthError.NETWORK, error)
    }

    // FEL fork: OAuth 2.0 device flow token exchange (RFC 8628). Waiting states arrive as HTTP 400.
    private suspend fun pollDeviceToken(deviceCode: String, authScope: SimklAuthScope): SimklPinPollResult {
        val response = try {
            executeAuthRequest(
                SimklApiRequest(
                    method = SimklHttpMethod.POST,
                    path = "/oauth2/token",
                    body = buildJsonObject {
                        put("grant_type", DEVICE_CODE_GRANT)
                        put("device_code", deviceCode)
                        put("client_id", configuration.clientId)
                    }.toString(),
                    requiresAuthentication = false,
                    retryPolicy = SimklRetryPolicy.NEVER
                )
            )
        } catch (error: SimklAuthException) {
            when (error.simklErrorCode()) {
                "authorization_pending", "slow_down" -> return SimklPinPollResult.Pending
                "expired_token" -> {
                    storage.clearPinSession(SimklAuthError.PIN_EXPIRED, authScope)
                    return SimklPinPollResult.Expired
                }
                "access_denied", "invalid_grant" -> {
                    storage.clearPinSession(SimklAuthError.PIN_INVALIDATED, authScope)
                    return SimklPinPollResult.Invalidated
                }
                else -> throw error
            }
        }
        val token = decodePinResponse(response.body).accessToken?.trim()?.takeIf(String::isNotBlank)
            ?: throw SimklAuthException(SimklAuthError.INVALID_PIN_RESPONSE)
        if (!storage.completePinAuthorization(token, authScope)) return SimklPinPollResult.Invalidated
        try {
            refreshUserSettings(scope = authScope)
        } catch (error: CancellationException) {
            throw error
        } catch (_: Throwable) {
            Unit
        }
        return SimklPinPollResult.Authorized
    }

    private fun SimklAuthException.simklErrorCode(): String? = (cause as? SimklApiException)?.errorCode

    private fun decodePinResponse(body: String): SimklPinResponse =
        runCatching { json.decodeFromString<SimklPinResponse>(body) }
            .getOrElse { throw SimklAuthException(SimklAuthError.INVALID_PIN_RESPONSE, it) }

    private companion object {
        val PIN_PATTERN = Regex("[A-Za-z0-9]{4,12}")
        const val DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
    }
}
