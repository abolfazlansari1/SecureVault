package com.example.securevault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.util.UUID

data class VaultItem(
    val id: String,
    val type: String, // "ACCOUNT" or "NOTE"
    val title: String,
    val emailOrUser: String,
    val secretOrBody: String,
    val extraNote: String
)

fun generateStrongPassword(length: Int = 16): String {
    val chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#\$%^&*"
    val random = SecureRandom()
    return buildString(length) {
        repeat(length) {
            append(chars[random.nextInt(chars.length)])
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

    fun loadItems(): List<VaultItem> {
        val rawJson = prefs.getString("vault_items_json", "[]") ?: "[]"
        return try {
            val array = JSONArray(rawJson)
            val result = mutableListOf<VaultItem>()
            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                result.add(
                    VaultItem(
                        id = obj.optString("id", UUID.randomUUID().toString()),
                        type = obj.optString("type", "ACCOUNT"),
                        title = obj.optString("title", ""),
                        emailOrUser = obj.optString("emailOrUser", ""),
                        secretOrBody = obj.optString("secretOrBody", ""),
                        extraNote = obj.optString("extraNote", "")
                    )
                )
            }
            result
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveItems(items: List<VaultItem>) {
        val array = JSONArray()
        items.forEach { item ->
            val obj = JSONObject().apply {
                put("id", item.id)
                put("type", item.type)
                put("title", item.title)
                put("emailOrUser", item.emailOrUser)
                put("secretOrBody", item.secretOrBody)
                put("extraNote", item.extraNote)
            }
            array.put(obj)
        }
        prefs.edit().putString("vault_items_json", array.toString()).apply()
    }
}

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val store = EncryptedVaultStore(this)

        setContent {
            VaultDarkTheme {
                var isUnlocked by remember { mutableStateOf(false) }
                var authError by remember { mutableStateOf<String?>(null) }
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

                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        if (event == Lifecycle.Event.ON_STOP) {
                            isUnlocked = false
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

                if (!isUnlocked) {
                    LockScreen(
                        errorMessage = authError,
                        onUnlockClick = { triggerBiometric() }
                    )
                } else {
                    VaultMainScreen(
                        store = store,
                        onLockApp = { isUnlocked = false }
                    )
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

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
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
    onLockApp: () -> Unit
) {
    val context = LocalContext.current
    var items by remember { mutableStateOf(store.loadItems()) }
    var selectedTab by remember { mutableIntStateOf(0) } // 0: Accounts, 1: Notes
    var searchQuery by remember { mutableStateOf("") }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingItem by remember { mutableStateOf<VaultItem?>(null) }

    val accountCount = remember(items) { items.count { it.type == "ACCOUNT" } }
    val noteCount = remember(items) { items.count { it.type == "NOTE" } }

    val filteredItems = remember(items, selectedTab, searchQuery) {
        val targetType = if (selectedTab == 0) "ACCOUNT" else "NOTE"
        items.filter { item ->
            item.type == targetType && (
                searchQuery.isBlank() ||
                    item.title.contains(searchQuery, ignoreCase = true) ||
                    item.emailOrUser.contains(searchQuery, ignoreCase = true) ||
                    item.extraNote.contains(searchQuery, ignoreCase = true) ||
                    (item.type == "NOTE" && item.secretOrBody.contains(searchQuery, ignoreCase = true))
                )
        }
    }

    fun copyToClipboard(label: String, value: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(context, "$label copied", Toast.LENGTH_SHORT).show()
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

            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = {
                    Text(
                        text = if (selectedTab == 0) "Search title, email, or username..." else "Search notes...",
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

            Spacer(Modifier.height(12.dp))

            if (filteredItems.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(
                            imageVector = if (selectedTab == 0) Icons.Outlined.Key else Icons.Outlined.Description,
                            contentDescription = null,
                            tint = Color(0xFF334155),
                            modifier = Modifier.size(56.dp)
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = if (selectedTab == 0) "No saved accounts yet" else "No encrypted notes yet",
                            color = Color(0xFF64748B),
                            fontSize = 14.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 92.dp)
                ) {
                    items(filteredItems, key = { it.id }) { item ->
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

    if (showAddDialog) {
        val defaultType = if (selectedTab == 0) "ACCOUNT" else "NOTE"
        VaultEditorDialog(
            initialItem = editingItem,
            defaultType = defaultType,
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
    var revealSecret by remember { mutableStateOf(false) }

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1420)),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF1E293B), RoundedCornerShape(16.dp))
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

            if (item.emailOrUser.isNotBlank()) {
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
                        text = item.emailOrUser,
                        color = Color(0xFFE2E8F0),
                        fontSize = 13.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = { onCopy("Username / Email", item.emailOrUser) },
                        modifier = Modifier.size(28.dp)
                    ) {
                        Icon(Icons.Outlined.ContentCopy, contentDescription = "Copy", tint = Color(0xFF38BDF8), modifier = Modifier.size(16.dp))
                    }
                }
            }

            if (item.secretOrBody.isNotBlank()) {
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
                    val displayedText = if (item.type == "ACCOUNT" && !revealSecret) {
                        "••••••••••••"
                    } else {
                        item.secretOrBody
                    }
                    Text(
                        text = displayedText,
                        color = Color(0xFFF1F5F9),
                        fontSize = 13.sp,
                        fontFamily = if (item.type == "ACCOUNT") FontFamily.Monospace else FontFamily.Default,
                        maxLines = if (item.type == "NOTE") 8 else 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    if (item.type == "ACCOUNT") {
                        IconButton(
                            onClick = { revealSecret = !revealSecret },
                            modifier = Modifier.size(28.dp)
                        ) {
                            Icon(
                                imageVector = if (revealSecret) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                contentDescription = "Toggle Visibility",
                                tint = Color(0xFF94A3B8),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    IconButton(
                        onClick = { onCopy(if (item.type == "ACCOUNT") "Password" else "Note", item.secretOrBody) },
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
    onDismiss: () -> Unit,
    onSave: (VaultItem) -> Unit
) {
    var selectedType by remember { mutableStateOf(initialItem?.type ?: defaultType) }
    var title by remember { mutableStateOf(initialItem?.title ?: "") }
    var emailOrUser by remember { mutableStateOf(initialItem?.emailOrUser ?: "") }
    var secretOrBody by remember { mutableStateOf(initialItem?.secretOrBody ?: "") }
    var extraNote by remember { mutableStateOf(initialItem?.extraNote ?: "") }
    var passwordVisible by remember { mutableStateOf(false) }

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
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = selectedType == "ACCOUNT",
                        onClick = { selectedType = "ACCOUNT" },
                        label = { Text("Account") }
                    )
                    FilterChip(
                        selected = selectedType == "NOTE",
                        onClick = { selectedType = "NOTE" },
                        label = { Text("Note") }
                    )
                }

                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title (e.g. Gmail, GitHub, Recovery)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                if (selectedType == "ACCOUNT") {
                    OutlinedTextField(
                        value = emailOrUser,
                        onValueChange = { emailOrUser = it },
                        label = { Text("Email / Username / Handle") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = secretOrBody,
                        onValueChange = { secretOrBody = it },
                        label = { Text("Password") },
                        singleLine = true,
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            Row {
                                IconButton(
                                    onClick = {
                                        secretOrBody = generateStrongPassword(16)
                                        passwordVisible = true
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
                } else {
                    OutlinedTextField(
                        value = secretOrBody,
                        onValueChange = { secretOrBody = it },
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
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    if (title.isNotBlank() || secretOrBody.isNotBlank() || emailOrUser.isNotBlank()) {
                        onSave(
                            VaultItem(
                                id = initialItem?.id ?: UUID.randomUUID().toString(),
                                type = selectedType,
                                title = title.ifBlank { if (selectedType == "ACCOUNT") "Untitled Account" else "Untitled Note" },
                                emailOrUser = emailOrUser.trim(),
                                secretOrBody = secretOrBody,
                                extraNote = extraNote.trim()
                            )
                        )
                    }
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
