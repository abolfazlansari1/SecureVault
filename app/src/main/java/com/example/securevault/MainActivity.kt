package com.example.securevault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.util.Base64
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class CustomField(
    val id: String = UUID.randomUUID().toString(),
    val label: String,
    val value: String
)

data class VaultItem(
    val id: String,
    val type: String, // "ACCOUNT" or "NOTE"
    val title: String,
    val password: String, // Required for ACCOUNT; note content for NOTE
    val customFields: List<CustomField> = emptyList(),
    val extraNote: String = "",
    val createdAt: Long = System.currentTimeMillis()
)

data class VaultSettings(
    val autoLockSeconds: Int = 0, // 0 = immediate on stop, 30, 120
    val clipboardClearSeconds: Int = 30, // 0 = off, 30, 60
    val passwordLength: Int = 16,
    val includeUpper: Boolean = true,
    val includeDigits: Boolean = true,
    val includeSymbols: Boolean = true
)

enum class SortOrder { NEWEST, OLDEST, TITLE_AZ }

fun generateCustomPassword(
    length: Int,
    includeUpper: Boolean,
    includeDigits: Boolean,
    includeSymbols: Boolean
): String {
    val lower = "abcdefghijklmnopqrstuvwxyz"
    val upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    val digits = "0123456789"
    val symbols = "!@#\$%^&*()-_=+?"

    val pool = buildString {
        append(lower)
        if (includeUpper) append(upper)
        if (includeDigits) append(digits)
        if (includeSymbols) append(symbols)
    }.ifEmpty { lower + digits }

    val random = SecureRandom()
    val required = mutableListOf<Char>().apply {
        add(lower[random.nextInt(lower.length)])
        if (includeUpper) add(upper[random.nextInt(upper.length)])
        if (includeDigits) add(digits[random.nextInt(digits.length)])
        if (includeSymbols) add(symbols[random.nextInt(symbols.length)])
    }

    val safeLength = length.coerceIn(6, 40)
    val result = mutableListOf<Char>().apply {
        addAll(required.take(safeLength))
        while (size < safeLength) {
            add(pool[random.nextInt(pool.length)])
        }
        shuffle(random)
    }
    return result.joinToString("")
}

fun passwordStrengthLabel(pw: String): Pair<String, Color> {
    if (pw.length < 8) return "Weak" to Color(0xFFF87171)
    var score = 0
    if (pw.length >= 12) score++
    if (pw.length >= 16) score++
    if (pw.any { it.isUpperCase() }) score++
    if (pw.any { it.isDigit() }) score++
    if (pw.any { !it.isLetterOrDigit() }) score++
    return when {
        score >= 4 -> "Strong" to Color(0xFF34D399)
        score >= 2 -> "Medium" to Color(0xFFFBBF24)
        else -> "Weak" to Color(0xFFF87171)
    }
}

object BackupCrypto {
    private fun deriveKey(passphrase: String, salt: ByteArray): SecretKeySpec {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        md.update(passphrase.toByteArray(StandardCharsets.UTF_8))
        var digest = md.digest()
        repeat(10000) {
            md.reset()
            md.update(digest)
            md.update(salt)
            digest = md.digest()
        }
        return SecretKeySpec(digest, "AES")
    }

    fun encryptBackup(plainText: String, passphrase: String): String {
        val random = SecureRandom()
        val salt = ByteArray(16).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val key = deriveKey(passphrase, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(plainText.toByteArray(StandardCharsets.UTF_8))

        val combined = ByteArray(salt.size + iv.size + encrypted.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(encrypted, 0, combined, salt.size + iv.size, encrypted.size)

        return "SVB1:" + Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptBackup(payload: String, passphrase: String): String? {
        return try {
            val trimmed = payload.trim().removePrefix("SVB1:")
            val combined = Base64.decode(trimmed, Base64.DEFAULT)
            if (combined.size < 29) return null
            val salt = combined.copyOfRange(0, 16)
            val iv = combined.copyOfRange(16, 28)
            val cipherText = combined.copyOfRange(28, combined.size)

            val key = deriveKey(passphrase, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            String(cipher.doFinal(cipherText), StandardCharsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }
}

class EncryptedVaultStore(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "secure_vault_encrypted_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun itemsToJson(items: List<VaultItem>): String {
        val array = JSONArray()
        items.forEach { item ->
            val fieldsArray = JSONArray()
            item.customFields.forEach { field ->
                fieldsArray.put(
                    JSONObject().apply {
                        put("id", field.id)
                        put("label", field.label)
                        put("value", field.value)
                    }
                )
            }
            val obj = JSONObject().apply {
                put("id", item.id)
                put("type", item.type)
                put("title", item.title)
                put("password", item.password)
                put("customFields", fieldsArray)
                put("extraNote", item.extraNote)
                put("createdAt", item.createdAt)
            }
            array.put(obj)
        }
        return array.toString()
    }

    fun jsonToItems(rawJson: String): List<VaultItem>? {
        return try {
            val array = JSONArray(rawJson)
            val result = mutableListOf<VaultItem>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                val fields = mutableListOf<CustomField>()
                val fieldsArr = obj.optJSONArray("customFields")
                if (fieldsArr != null) {
                    for (j in 0 until fieldsArr.length()) {
                        val fObj = fieldsArr.getJSONObject(j)
                        fields.add(
                            CustomField(
                                id = fObj.optString("id", UUID.randomUUID().toString()),
                                label = fObj.optString("label", ""),
                                value = fObj.optString("value", "")
                            )
                        )
                    }
                }
                val legacyEmailUser = obj.optString("emailOrUser", "")
                if (legacyEmailUser.isNotBlank() && fields.none { it.label.equals("Email / User", true) }) {
                    fields.add(0, CustomField(label = "Email / User", value = legacyEmailUser))
                }
                val secret = if (obj.has("password")) obj.optString("password", "")
                else obj.optString("secretOrBody", "")

                result.add(
                    VaultItem(
                        id = obj.optString("id", UUID.randomUUID().toString()),
                        type = obj.optString("type", "ACCOUNT"),
                        title = obj.optString("title", ""),
                        password = secret,
                        customFields = fields,
                        extraNote = obj.optString("extraNote", ""),
                        createdAt = obj.optLong("createdAt", System.currentTimeMillis())
                    )
                )
            }
            result
        } catch (_: Exception) {
            null
        }
    }

    fun loadItems(): List<VaultItem> {
        val rawJson = prefs.getString("vault_items_json", "[]") ?: "[]"
        return jsonToItems(rawJson) ?: emptyList()
    }

    fun saveItems(items: List<VaultItem>) {
        prefs.edit().putString("vault_items_json", itemsToJson(items)).apply()
    }

    fun wipeAllItems() {
        prefs.edit().remove("vault_items_json").apply()
    }

    fun loadSettings(): VaultSettings {
        return VaultSettings(
            autoLockSeconds = prefs.getInt("auto_lock_sec", 0),
            clipboardClearSeconds = prefs.getInt("clip_clear_sec", 30),
            passwordLength = prefs.getInt("pw_len", 16),
            includeUpper = prefs.getBoolean("pw_upper", true),
            includeDigits = prefs.getBoolean("pw_digits", true),
            includeSymbols = prefs.getBoolean("pw_symbols", true)
        )
    }

    fun saveSettings(s: VaultSettings) {
        prefs.edit()
            .putInt("auto_lock_sec", s.autoLockSeconds)
            .putInt("clip_clear_sec", s.clipboardClearSeconds)
            .putInt("pw_len", s.passwordLength)
            .putBoolean("pw_upper", s.includeUpper)
            .putBoolean("pw_digits", s.includeDigits)
            .putBoolean("pw_symbols", s.includeSymbols)
            .apply()
    }
}

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        enableEdgeToEdge()
        val store = EncryptedVaultStore(this)

        setContent {
            VaultDarkTheme {
                var settings by remember { mutableStateOf(store.loadSettings()) }
                var isUnlocked by remember { mutableStateOf(false) }
                var authError by remember { mutableStateOf<String?>(null) }
                var backgroundTimestamp by remember { mutableStateOf<Long?>(null) }
                val lifecycleOwner = LocalLifecycleOwner.current

                fun triggerBiometric() {
                    val biometricManager = BiometricManager.from(this@MainActivity)
                    val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL

                    when (biometricManager.canAuthenticate(authenticators)) {
                        BiometricManager.BIOMETRIC_SUCCESS -> {
                            val executor = ContextCompat.getMainExecutor(this@MainActivity)
                            val prompt = BiometricPrompt(
                                this@MainActivity,
                                executor,
                                object : BiometricPrompt.AuthenticationCallback() {
                                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                        super.onAuthenticationSucceeded(result)
                                        authError = null
                                        backgroundTimestamp = null
                                        isUnlocked = true
                                    }

                                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                        super.onAuthenticationError(errorCode, errString)
                                        authError = errString.toString()
                                    }

                                    override fun onAuthenticationFailed() {
                                        super.onAuthenticationFailed()
                                        authError = "Authentication failed. Please try again."
                                    }
                                }
                            )

                            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                                .setTitle("Unlock SecureVault")
                                .setSubtitle("Authenticate with fingerprint or device screen lock")
                                .setAllowedAuthenticators(authenticators)
                                .build()

                            prompt.authenticate(promptInfo)
                        }
                        else -> {
                            authError = "No screen lock or biometric enrolled; unlocked locally."
                            isUnlocked = true
                        }
                    }
                }

                DisposableEffect(lifecycleOwner, settings.autoLockSeconds) {
                    val observer = LifecycleEventObserver { _, event ->
                        when (event) {
                            Lifecycle.Event.ON_STOP -> {
                                if (settings.autoLockSeconds == 0) {
                                    isUnlocked = false
                                } else {
                                    backgroundTimestamp = System.currentTimeMillis()
                                }
                            }
                            Lifecycle.Event.ON_START -> {
                                val bg = backgroundTimestamp
                                if (bg != null && settings.autoLockSeconds > 0) {
                                    val elapsedSec = (System.currentTimeMillis() - bg) / 1000
                                    if (elapsedSec >= settings.autoLockSeconds) {
                                        isUnlocked = false
                                    }
                                }
                            }
                            else -> Unit
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose {
                        lifecycleOwner.lifecycle.removeObserver(observer)
                    }
                }

                LaunchedEffect(isUnlocked) {
                    if (!isUnlocked) {
                        triggerBiometric()
                    }
                }

                AnimatedContent(
                    targetState = isUnlocked,
                    transitionSpec = {
                        (fadeIn(tween(240)) + slideInVertically(tween(240)) { it / 16 })
                            .togetherWith(fadeOut(tween(180)) + slideOutVertically(tween(180)) { -it / 16 })
                    },
                    label = "LockTransition"
                ) { unlocked ->
                    if (!unlocked) {
                        LockScreen(
                            errorMessage = authError,
                            onUnlockClick = { triggerBiometric() }
                        )
                    } else {
                        VaultMainScreen(
                            store = store,
                            settings = settings,
                            onUpdateSettings = { updated ->
                                settings = updated
                                store.saveSettings(updated)
                            },
                            onLockApp = {
                                backgroundTimestamp = null
                                isUnlocked = false
                            }
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun VaultDarkTheme(content: @Composable () -> Unit) {
    val colorScheme = darkColorScheme(
        primary = Color(0xFF38BDF8),
        onPrimary = Color(0xFF06131A),
        secondary = Color(0xFF818CF8),
        background = Color(0xFF070A10),
        surface = Color(0xFF0F1420),
        surfaceVariant = Color(0xFF171E2E),
        onBackground = Color(0xFFF8FAFC),
        onSurface = Color(0xFFF8FAFC),
        onSurfaceVariant = Color(0xFF94A3B8),
        outline = Color(0xFF1E293B)
    )

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

@Composable
fun LockScreen(
    errorMessage: String?,
    onUnlockClick: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0xFF070A10), Color(0xFF0E172A), Color(0xFF070A10))
                )
            )
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .size(96.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF111C33))
                    .border(1.5.dp, Color(0xFF38BDF8).copy(alpha = 0.65f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Fingerprint,
                    contentDescription = "Unlock",
                    tint = Color(0xFF38BDF8),
                    modifier = Modifier.size(54.dp)
                )
            }

            Text(
                text = "SECURE VAULT",
                color = Color.White,
                fontSize = 24.sp,
                fontWeight = FontWeight.ExtraBold,
                letterSpacing = 2.sp
            )

            Surface(
                shape = RoundedCornerShape(999.dp),
                color = Color(0xFF111C33)
            ) {
                Text(
                    text = "AES-256 ENCRYPTED • OFFLINE LOCAL STORAGE",
                    color = Color(0xFF38BDF8),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                )
            }

            AnimatedVisibility(visible = errorMessage != null) {
                Text(
                    text = errorMessage ?: "",
                    color = Color(0xFFF87171),
                    fontSize = 12.sp
                )
            }

            Spacer(Modifier.height(4.dp))

            Button(
                onClick = onUnlockClick,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF38BDF8),
                    contentColor = Color(0xFF06131A)
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp)
            ) {
                Icon(Icons.Filled.LockOpen, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Unlock with Biometrics / PIN", fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultMainScreen(
    store: EncryptedVaultStore,
    settings: VaultSettings,
    onUpdateSettings: (VaultSettings) -> Unit,
    onLockApp: () -> Unit
) {
    val context = LocalContext.current
    var items by remember { mutableStateOf(store.loadItems()) }
    var selectedTab by remember { mutableIntStateOf(0) } // 0: Accounts, 1: Notes
    var searchQuery by remember { mutableStateOf("") }
    var sortOrder by remember { mutableStateOf(SortOrder.NEWEST) }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingItem by remember { mutableStateOf<VaultItem?>(null) }
    var showSettingsSheet by remember { mutableStateOf(false) }

    val accountCount = remember(items) { items.count { it.type == "ACCOUNT" } }
    val noteCount = remember(items) { items.count { it.type == "NOTE" } }

    val filteredItems = remember(items, selectedTab, searchQuery, sortOrder) {
        val targetType = if (selectedTab == 0) "ACCOUNT" else "NOTE"
        val base = items.filter { item ->
            item.type == targetType && (
                searchQuery.isBlank() ||
                    item.title.contains(searchQuery, ignoreCase = true) ||
                    item.extraNote.contains(searchQuery, ignoreCase = true) ||
                    item.customFields.any {
                        it.label.contains(searchQuery, ignoreCase = true) ||
                            it.value.contains(searchQuery, ignoreCase = true)
                    } ||
                    (item.type == "NOTE" && item.password.contains(searchQuery, ignoreCase = true))
                )
        }
        when (sortOrder) {
            SortOrder.NEWEST -> base.sortedByDescending { it.createdAt }
            SortOrder.OLDEST -> base.sortedBy { it.createdAt }
            SortOrder.TITLE_AZ -> base.sortedBy { it.title.lowercase() }
        }
    }

    fun copyToClipboard(label: String, value: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, value).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        if (settings.clipboardClearSeconds > 0) {
            Toast.makeText(
                context,
                "$label copied (clears in ${settings.clipboardClearSeconds}s)",
                Toast.LENGTH_SHORT
            ).show()
            Handler(Looper.getMainLooper()).postDelayed({
                try {
                    val current = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
                    if (current == value) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            clipboard.clearPrimaryClip()
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                    }
                } catch (_: Exception) {
                }
            }, settings.clipboardClearSeconds * 1000L)
        } else {
            Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        containerColor = Color(0xFF070A10),
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0B101B),
                    titleContentColor = Color.White
                ),
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(34.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color(0xFF132238)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = Color(0xFF38BDF8),
                                modifier = Modifier.size(19.dp)
                            )
                        }
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "SecureVault",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Offline • AES-256",
                                fontSize = 11.sp,
                                color = Color(0xFF38BDF8)
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { showSettingsSheet = true }) {
                        Icon(
                            imageVector = Icons.Outlined.Settings,
                            contentDescription = "Settings",
                            tint = Color(0xFF94A3B8)
                        )
                    }
                    IconButton(onClick = onLockApp) {
                        Icon(
                            imageVector = Icons.Filled.Lock,
                            contentDescription = "Lock Vault",
                            tint = Color(0xFF94A3B8)
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = {
                    editingItem = null
                    showAddDialog = true
                },
                containerColor = Color(0xFF38BDF8),
                contentColor = Color(0xFF06131A),
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add")
                Spacer(Modifier.width(6.dp))
                Text(
                    text = if (selectedTab == 0) "New Account" else "New Note",
                    fontWeight = FontWeight.Bold
                )
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(Color(0xFF101624))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                TabPill(
                    text = "Accounts ($accountCount)",
                    selected = selectedTab == 0,
                    modifier = Modifier.weight(1f),
                    onClick = { selectedTab = 0 }
                )
                TabPill(
                    text = "Notes ($noteCount)",
                    selected = selectedTab == 1,
                    modifier = Modifier.weight(1f),
                    onClick = { selectedTab = 1 }
                )
            }

            Spacer(Modifier.height(10.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = {
                    Text(
                        text = if (selectedTab == 0) "Search title, custom fields, or tags..." else "Search notes...",
                        color = Color(0xFF64748B),
                        fontSize = 13.sp
                    )
                },
                leadingIcon = {
                    Icon(Icons.Outlined.Search, contentDescription = null, tint = Color(0xFF94A3B8))
                },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "Clear", tint = Color(0xFF94A3B8))
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = Color(0xFF0F1420),
                    unfocusedContainerColor = Color(0xFF0F1420),
                    focusedBorderColor = Color(0xFF38BDF8),
                    unfocusedBorderColor = Color(0xFF1E293B),
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(8.dp))

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Outlined.Sort, contentDescription = null, tint = Color(0xFF64748B), modifier = Modifier.size(16.dp))
                FilterChip(
                    selected = sortOrder == SortOrder.NEWEST,
                    onClick = { sortOrder = SortOrder.NEWEST },
                    label = { Text("Newest", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = sortOrder == SortOrder.OLDEST,
                    onClick = { sortOrder = SortOrder.OLDEST },
                    label = { Text("Oldest", fontSize = 11.sp) }
                )
                FilterChip(
                    selected = sortOrder == SortOrder.TITLE_AZ,
                    onClick = { sortOrder = SortOrder.TITLE_AZ },
                    label = { Text("A-Z", fontSize = 11.sp) }
                )
            }

            Spacer(Modifier.height(8.dp))

            AnimatedContent(
                targetState = selectedTab,
                transitionSpec = {
                    fadeIn(tween(200)) togetherWith fadeOut(tween(150))
                },
                label = "TabContent",
                modifier = Modifier.fillMaxSize()
            ) { currentTab ->
                val listForTab = remember(filteredItems, currentTab) { filteredItems }
                if (listForTab.isEmpty()) {
                    Box(
                        modifier = Modifier.fillMaxSize(),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                imageVector = if (currentTab == 0) Icons.Outlined.Key else Icons.Outlined.Description,
                                contentDescription = null,
                                tint = Color(0xFF334155),
                                modifier = Modifier.size(56.dp)
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = if (currentTab == 0) "No saved accounts yet" else "No encrypted notes yet",
                                color = Color(0xFF64748B),
                                fontSize = 14.sp
                            )
                        }
                    }
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                        contentPadding = PaddingValues(bottom = 92.dp),
                        modifier = Modifier.fillMaxSize()
                    ) {
                        items(listForTab, key = { it.id }) { item ->
                            VaultCard(
                                item = item,
                                onCopy = { label, text -> copyToClipboard(label, text) },
                                onEdit = {
                                    editingItem = item
                                    showAddDialog = true
                                },
                                onDelete = {
                                    val updated = items.filterNot { it.id == item.id }
                                    items = updated
                                    store.saveItems(updated)
                                }
                            )
                        }
                    }
                }
            }
        }
    }

    if (showAddDialog) {
        val defaultType = if (selectedTab == 0) "ACCOUNT" else "NOTE"
        VaultEditorDialog(
            initialItem = editingItem,
            defaultType = defaultType,
            settings = settings,
            onDismiss = {
                showAddDialog = false
                editingItem = null
            },
            onSave = { saved ->
                val updated = if (editingItem != null) {
                    items.map { if (it.id == saved.id) saved else it }
                } else {
                    listOf(saved) + items
                }
                items = updated
                store.saveItems(updated)
                showAddDialog = false
                editingItem = null
            }
        )
    }

    if (showSettingsSheet) {
        VaultSettingsDialog(
            store = store,
            settings = settings,
            currentItems = items,
            onUpdateSettings = onUpdateSettings,
            onImportItems = { imported ->
                items = imported
                store.saveItems(imported)
            },
            onWipeItems = {
                items = emptyList()
                store.wipeAllItems()
            },
            onDismiss = { showSettingsSheet = false }
        )
    }
}

@Composable
fun TabPill(
    text: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(11.dp))
            .background(if (selected) Color(0xFF1A253A) else Color.Transparent)
            .border(
                width = if (selected) 1.dp else 0.dp,
                color = if (selected) Color(0xFF38BDF8).copy(alpha = 0.5f) else Color.Transparent,
                shape = RoundedCornerShape(11.dp)
            )
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = if (selected) Color.White else Color(0xFF94A3B8),
            fontSize = 13.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}

@Composable
fun VaultCard(
    item: VaultItem,
    onCopy: (String, String) -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    var revealPassword by remember { mutableStateOf(false) }

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1420)),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF1E293B), RoundedCornerShape(16.dp))
            .animateContentSize(animationSpec = tween(220))
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f)
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFF162238)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (item.type == "ACCOUNT") Icons.Filled.Key else Icons.Filled.Description,
                            contentDescription = null,
                            tint = Color(0xFF38BDF8),
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text = item.title,
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Row {
                    IconButton(onClick = onEdit, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Outlined.Edit, contentDescription = "Edit", tint = Color(0xFF94A3B8), modifier = Modifier.size(18.dp))
                    }
                    IconButton(onClick = onDelete, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Outlined.Delete, contentDescription = "Delete", tint = Color(0xFFF87171), modifier = Modifier.size(18.dp))
                    }
                }
            }

            if (item.type == "ACCOUNT") {
                Spacer(Modifier.height(8.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFF090D16))
                        .padding(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Password",
                            color = Color(0xFF38BDF8),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = if (revealPassword) item.password else "••••••••••••",
                            color = Color(0xFFF1F5F9),
                            fontSize = 13.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    IconButton(
                        onClick = { revealPassword = !revealPassword },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(
                            imageVector = if (revealPassword) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                            contentDescription = "Toggle Password",
                            tint = Color(0xFF94A3B8),
                            modifier = Modifier.size(16.dp)
                        )
                    }
                    IconButton(
                        onClick = { onCopy("Password", item.password) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy", tint = Color(0xFF38BDF8), modifier = Modifier.size(16.dp))
                    }
                }

                item.customFields.filter { it.label.isNotBlank() || it.value.isNotBlank() }.forEach { field ->
                    Spacer(Modifier.height(6.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(Color(0xFF090D16))
                            .padding(horizontal = 10.dp, vertical = 8.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = field.label.ifBlank { "Custom Field" },
                                color = Color(0xFF94A3B8),
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Medium
                            )
                            Text(
                                text = field.value,
                                color = Color(0xFFE2E8F0),
                                fontSize = 13.sp,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        if (field.value.isNotBlank()) {
                            IconButton(
                                onClick = { onCopy(field.label.ifBlank { "Field" }, field.value) },
                                modifier = Modifier.size(28.dp)
                            ) {
                                Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy", tint = Color(0xFF38BDF8), modifier = Modifier.size(16.dp))
                            }
                        }
                    }
                }
            } else if (item.password.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Color(0xFF090D16))
                        .padding(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = item.password,
                        color = Color(0xFFF1F5F9),
                        fontSize = 13.sp,
                        maxLines = 10,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = { onCopy("Note", item.password) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy", tint = Color(0xFF38BDF8), modifier = Modifier.size(16.dp))
                    }
                }
            }

            if (item.extraNote.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = item.extraNote,
                    color = Color(0xFF94A3B8),
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
fun VaultEditorDialog(
    initialItem: VaultItem?,
    defaultType: String,
    settings: VaultSettings,
    onDismiss: () -> Unit,
    onSave: (VaultItem) -> Unit
) {
    var selectedType by remember { mutableStateOf(initialItem?.type ?: defaultType) }
    var title by remember { mutableStateOf(initialItem?.title ?: "") }
    var password by remember { mutableStateOf(initialItem?.password ?: "") }
    var extraNote by remember { mutableStateOf(initialItem?.extraNote ?: "") }
    var passwordVisible by remember { mutableStateOf(false) }
    var validationError by remember { mutableStateOf<String?>(null) }

    val customFields = remember {
        mutableStateListOf<CustomField>().apply {
            if (initialItem != null && initialItem.customFields.isNotEmpty()) {
                addAll(initialItem.customFields)
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF101624),
        titleContentColor = Color.White,
        title = {
            Text(
                text = if (initialItem != null) "Edit Entry" else "Create Entry",
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )
        },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .animateContentSize()
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = selectedType == "ACCOUNT",
                        onClick = {
                            selectedType = "ACCOUNT"
                            validationError = null
                        },
                        label = { Text("Account") }
                    )
                    FilterChip(
                        selected = selectedType == "NOTE",
                        onClick = {
                            selectedType = "NOTE"
                            validationError = null
                        },
                        label = { Text("Note") }
                    )
                }

                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title (e.g. Gmail, GitHub, Steam)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                if (selectedType == "ACCOUNT") {
                    OutlinedTextField(
                        value = password,
                        onValueChange = {
                            password = it
                            validationError = null
                        },
                        label = { Text("Password * (Required)") },
                        singleLine = true,
                        isError = validationError != null && password.isBlank(),
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            Row {
                                IconButton(
                                    onClick = {
                                        password = generateCustomPassword(
                                            length = settings.passwordLength,
                                            includeUpper = settings.includeUpper,
                                            includeDigits = settings.includeDigits,
                                            includeSymbols = settings.includeSymbols
                                        )
                                        passwordVisible = true
                                        validationError = null
                                    }
                                ) {
                                    Icon(Icons.Outlined.AutoAwesome, contentDescription = "Generate Password", tint = Color(0xFF38BDF8))
                                }
                                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                    Icon(
                                        imageVector = if (passwordVisible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                        contentDescription = "Toggle Password"
                                    )
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )

                    if (password.isNotEmpty()) {
                        val (strength, sColor) = passwordStrengthLabel(password)
                        Text(
                            text = "Strength: $strength",
                            color = sColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    customFields.forEachIndexed { index, field ->
                        Column(
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(Color(0xFF0B0F19))
                                .border(1.dp, Color(0xFF1E293B), RoundedCornerShape(12.dp))
                                .padding(8.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                OutlinedTextField(
                                    value = field.label,
                                    onValueChange = { newLabel ->
                                        customFields[index] = field.copy(label = newLabel)
                                    },
                                    label = { Text("Field Name (e.g. Email, PIN)") },
                                    singleLine = true,
                                    modifier = Modifier.weight(1f)
                                )
                                IconButton(onClick = { customFields.removeAt(index) }) {
                                    Icon(
                                        imageVector = Icons.Outlined.DeleteOutline,
                                        contentDescription = "Remove Field",
                                        tint = Color(0xFFF87171)
                                    )
                                }
                            }

                            OutlinedTextField(
                                value = field.value,
                                onValueChange = { newVal ->
                                    customFields[index] = field.copy(value = newVal)
                                },
                                label = { Text("Field Value") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }

                    OutlinedButton(
                        onClick = {
                            customFields.add(CustomField(label = "", value = ""))
                        },
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("Add Custom Input")
                    }
                } else {
                    OutlinedTextField(
                        value = password,
                        onValueChange = {
                            password = it
                            validationError = null
                        },
                        label = { Text("Encrypted Note Content") },
                        minLines = 3,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                OutlinedTextField(
                    value = extraNote,
                    onValueChange = { extraNote = it },
                    label = { Text("Extra Tag / Remark (Optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                AnimatedVisibility(
                    visible = validationError != null,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    Text(
                        text = validationError ?: "",
                        color = Color(0xFFF87171),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (selectedType == "ACCOUNT" && password.isBlank()) {
                        validationError = "Password is required for an account."
                        return@Button
                    }
                    if (selectedType == "NOTE" && title.isBlank() && password.isBlank()) {
                        validationError = "Please enter a title or note content."
                        return@Button
                    }
                    onSave(
                        VaultItem(
                            id = initialItem?.id ?: UUID.randomUUID().toString(),
                            type = selectedType,
                            title = title.trim().ifBlank {
                                if (selectedType == "ACCOUNT") "Untitled Account" else "Untitled Note"
                            },
                            password = password,
                            customFields = if (selectedType == "ACCOUNT") {
                                customFields.filter { it.label.isNotBlank() || it.value.isNotBlank() }
                            } else {
                                emptyList()
                            },
                            extraNote = extraNote.trim(),
                            createdAt = initialItem?.createdAt ?: System.currentTimeMillis()
                        )
                    )
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF38BDF8),
                    contentColor = Color(0xFF06131A)
                )
            ) {
                Text("Save Encrypted", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = Color(0xFF94A3B8))
            }
        }
    )
}

@Composable
fun VaultSettingsDialog(
    store: EncryptedVaultStore,
    settings: VaultSettings,
    currentItems: List<VaultItem>,
    onUpdateSettings: (VaultSettings) -> Unit,
    onImportItems: (List<VaultItem>) -> Unit,
    onWipeItems: () -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var draft by remember { mutableStateOf(settings) }
    var passphrase by remember { mutableStateOf("") }
    var backupBlob by remember { mutableStateOf("") }
    var statusMsg by remember { mutableStateOf<String?>(null) }
    var confirmWipe by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Color(0xFF101624),
        titleContentColor = Color.White,
        title = { Text("Security & Backup", fontWeight = FontWeight.Bold, fontSize = 18.sp) },
        text = {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .animateContentSize()
            ) {
                Text("Auto-Lock Timer", color = Color(0xFF38BDF8), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf(0 to "Instant", 30 to "30s", 120 to "2m").forEach { (sec, label) ->
                        FilterChip(
                            selected = draft.autoLockSeconds == sec,
                            onClick = { draft = draft.copy(autoLockSeconds = sec) },
                            label = { Text(label, fontSize = 11.sp) }
                        )
                    }
                }

                Text("Clipboard Auto-Clear", color = Color(0xFF38BDF8), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf(0 to "Off", 30 to "30s", 60 to "60s").forEach { (sec, label) ->
                        FilterChip(
                            selected = draft.clipboardClearSeconds == sec,
                            onClick = { draft = draft.copy(clipboardClearSeconds = sec) },
                            label = { Text(label, fontSize = 11.sp) }
                        )
                    }
                }

                Text("Password Generator (${draft.passwordLength} chars)", color = Color(0xFF38BDF8), fontSize = 12.sp, fontWeight = FontWeight.Bold)
                Slider(
                    value = draft.passwordLength.toFloat(),
                    onValueChange = { draft = draft.copy(passwordLength = it.toInt()) },
                    valueRange = 8f..32f
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = draft.includeUpper,
                        onClick = { draft = draft.copy(includeUpper = !draft.includeUpper) },
                        label = { Text("A-Z", fontSize = 11.sp) }
                    )
                    FilterChip(
                        selected = draft.includeDigits,
                        onClick = { draft = draft.copy(includeDigits = !draft.includeDigits) },
                        label = { Text("0-9", fontSize = 11.sp) }
                    )
                    FilterChip(
                        selected = draft.includeSymbols,
                        onClick = { draft = draft.copy(includeSymbols = !draft.includeSymbols) },
                        label = { Text("!@#", fontSize = 11.sp) }
                    )
                }

                HorizontalDivider(color = Color(0xFF1E293B))
                Text("Encrypted Offline Backup / Restore", color = Color(0xFF38BDF8), fontSize = 12.sp, fontWeight = FontWeight.Bold)

                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Backup Passphrase") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedButton(
                        onClick = {
                            if (passphrase.length < 4) {
                                statusMsg = "Enter at least 4 characters for passphrase."
                            } else {
                                backupBlob = BackupCrypto.encryptBackup(store.itemsToJson(currentItems), passphrase)
                                val clip = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clip.setPrimaryClip(ClipData.newPlainText("SecureVault Backup", backupBlob))
                                statusMsg = "Encrypted backup generated & copied."
                            }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Export", fontSize = 12.sp)
                    }

                    OutlinedButton(
                        onClick = {
                            val decrypted = BackupCrypto.decryptBackup(backupBlob, passphrase)
                            val parsed = decrypted?.let { store.jsonToItems(it) }
                            if (parsed != null) {
                                onImportItems(parsed)
                                statusMsg = "Restored ${parsed.size} items."
                            } else {
                                statusMsg = "Invalid passphrase or backup text."
                            }
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Import", fontSize = 12.sp)
                    }
                }

                OutlinedTextField(
                    value = backupBlob,
                    onValueChange = { backupBlob = it },
                    label = { Text("Encrypted Backup String (SVB1:...)") },
                    minLines = 2,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth()
                )

                if (statusMsg != null) {
                    Text(statusMsg ?: "", color = Color(0xFF38BDF8), fontSize = 11.sp)
                }

                HorizontalDivider(color = Color(0xFF1E293B))
                if (!confirmWipe) {
                    TextButton(onClick = { confirmWipe = true }) {
                        Icon(Icons.Outlined.DeleteForever, contentDescription = null, tint = Color(0xFFF87171))
                        Spacer(Modifier.width(6.dp))
                        Text("Wipe All Local Vault Data", color = Color(0xFFF87171), fontSize = 12.sp)
                    }
                } else {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = {
                                onWipeItems()
                                confirmWipe = false
                                statusMsg = "All items wiped."
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFDC2626))
                        ) {
                            Text("Confirm Wipe", fontSize = 12.sp)
                        }
                        TextButton(onClick = { confirmWipe = false }) {
                            Text("Cancel", fontSize = 12.sp)
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onUpdateSettings(draft)
                    onDismiss()
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF38BDF8),
                    contentColor = Color(0xFF06131A)
                )
            ) {
                Text("Apply", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close", color = Color(0xFF94A3B8))
            }
        }
    )
}
