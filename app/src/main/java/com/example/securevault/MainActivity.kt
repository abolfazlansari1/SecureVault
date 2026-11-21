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
import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class VaultItem(
    val id: String,
    val type: String, // "ACCOUNT" or "NOTE"
    val title: String,
    val emailOrUser: String,
    val secretOrBody: String,
    val extraNote: String
)

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
                                        authError = "تطابق انجام نشد. دوباره تلاش کن."
                                    }
                                }
                            )

                            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                                .setTitle("قفل امنیتی SecureVault")
                                .setSubtitle("اثر انگشت یا رمز قفل گوشی را وارد کن")
                                .setAllowedAuthenticators(authenticators)
                                .build()

                            prompt.authenticate(promptInfo)
                        }
                        else -> {
                            // اگر قفل بیومتریک/رمزی روی دستگاه فعال نبود، اجازه ورود محلی داده می‌شود
                            authError = "قفل بیومتریک یا رمز صفحه روی گوشی تنظیم نیست؛ ورود مستقیم انجام شد."
                            isUnlocked = true
                        }
                    }
                }

                LaunchedEffect(Unit) {
                    triggerBiometric()
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
        secondary = Color(0xFFA855F7),
        background = Color(0xFF090B10),
        surface = Color(0xFF111520),
        surfaceVariant = Color(0xFF181D2B),
        onBackground = Color(0xFFF3F4F6),
        onSurface = Color(0xFFF3F4F6),
        onSurfaceVariant = Color(0xFF9CA3AF),
        outline = Color(0xFF262D40)
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
                    colors = listOf(Color(0xFF090B10), Color(0xFF101729), Color(0xFF090B10))
                )
            )
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(92.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF151C2E))
                    .border(1.5.dp, Color(0xFF38BDF8).copy(alpha = 0.6f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Filled.Fingerprint,
                    contentDescription = "Unlock",
                    tint = Color(0xFF38BDF8),
                    modifier = Modifier.size(52.dp)
                )
            }

            Text(
                text = "SECURE VAULT",
                color = Color.White,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp
            )

            Text(
                text = "دیتاهای رمزنگاری‌شده AES-256 • کاملاً آفلاین",
                color = Color(0xFF9CA3AF),
                fontSize = 13.sp
            )

            if (errorMessage != null) {
                Text(
                    text = errorMessage,
                    color = Color(0xFFF87171),
                    fontSize = 12.sp
                )
            }

            Button(
                onClick = onUnlockClick,
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF38BDF8),
                    contentColor = Color(0xFF06131A)
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Icon(Icons.Filled.LockOpen, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("باز کردن با اثر انگشت / رمز گوشی", fontWeight = FontWeight.SemiBold)
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

    val filteredItems = remember(items, selectedTab, searchQuery) {
        val targetType = if (selectedTab == 0) "ACCOUNT" else "NOTE"
        items.filter { item ->
            item.type == targetType && (
                searchQuery.isBlank() ||
                    item.title.contains(searchQuery, ignoreCase = true) ||
                    item.emailOrUser.contains(searchQuery, ignoreCase = true) ||
                    item.extraNote.contains(searchQuery, ignoreCase = true)
                )
        }
    }

    fun copyToClipboard(label: String, value: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
        Toast.makeText(context, "$label کپی شد", Toast.LENGTH_SHORT).show()
    }

    Scaffold(
        containerColor = Color(0xFF090B10),
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF0D111A),
                    titleContentColor = Color.White
                ),
                title = {
                    Column {
                        Text(
                            text = "SecureVault",
                            fontSize = 19.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "آفلاین • رمزنگاری AES-256",
                            fontSize = 11.sp,
                            color = Color(0xFF38BDF8)
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onLockApp) {
                        Icon(
                            imageVector = Icons.Filled.Lock,
                            contentDescription = "Lock",
                            tint = Color(0xFF9CA3AF)
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    editingItem = null
                    showAddDialog = true
                },
                containerColor = Color(0xFF38BDF8),
                contentColor = Color(0xFF06131A),
                shape = RoundedCornerShape(16.dp)
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add")
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
        ) {
            Spacer(Modifier.height(10.dp))

            // تب‌های اکانت‌ها و یادداشت‌ها
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(Color(0xFF121724))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                TabPill(
                    text = "اکانت‌ها و پسوردها",
                    selected = selectedTab == 0,
                    modifier = Modifier.weight(1f),
                    onClick = { selectedTab = 0 }
                )
                TabPill(
                    text = "یادداشت‌های امن",
                    selected = selectedTab == 1,
                    modifier = Modifier.weight(1f),
                    onClick = { selectedTab = 1 }
                )
            }

            Spacer(Modifier.height(12.dp))

            // باکس جستجو
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("جستجو در عنوان، جیمیل یا یوزرنیم...", color = Color(0xFF6B7280), fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Outlined.Search, contentDescription = null, tint = Color(0xFF9CA3AF)) },
                trailingIcon = {
                    if (searchQuery.isNotEmpty()) {
                        IconButton(onClick = { searchQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = null, tint = Color(0xFF9CA3AF))
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = Color(0xFF111520),
                    unfocusedContainerColor = Color(0xFF111520),
                    focusedBorderColor = Color(0xFF38BDF8),
                    unfocusedBorderColor = Color(0xFF1F2637),
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
                            tint = Color(0xFF374151),
                            modifier = Modifier.size(56.dp)
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = if (selectedTab == 0) "هنوز اکانتی ثبت نشده است" else "هنوز یادداشتی ثبت نشده است",
                            color = Color(0xFF6B7280),
                            fontSize = 14.sp
                        )
                    }
                }
            } else {
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    contentPadding = PaddingValues(bottom = 84.dp)
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
            .background(if (selected) Color(0xFF1D273B) else Color.Transparent)
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
            color = if (selected) Color.White else Color(0xFF9CA3AF),
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
        colors = CardDefaults.cardColors(containerColor = Color(0xFF111520)),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFF1E2638), RoundedCornerShape(16.dp))
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
                            .background(Color(0xFF182235)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (item.type == "ACCOUNT") Icons.Filled.Shield else Icons.Filled.EditNote,
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
                        Icon(Icons.Outlined.Edit, contentDescription = "Edit", tint = Color(0xFF9CA3AF), modifier = Modifier.size(18.dp))
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
                        .background(Color(0xFF0C0F17))
                        .padding(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    Text(
                        text = item.emailOrUser,
                        color = Color(0xFFD1D5DB),
                        fontSize = 13.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(
                        onClick = { onCopy("حساب / جیمیل", item.emailOrUser) },
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
                        .background(Color(0xFF0C0F17))
                        .padding(horizontal = 10.dp, vertical = 8.dp)
                ) {
                    val displayedText = if (item.type == "ACCOUNT" && !revealSecret) {
                        "••••••••••••"
                    } else {
                        item.secretOrBody
                    }
                    Text(
                        text = displayedText,
                        color = Color(0xFFE5E7EB),
                        fontSize = 13.sp,
                        maxLines = if (item.type == "NOTE") 6 else 1,
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
                                contentDescription = "Toggle",
                                tint = Color(0xFF9CA3AF),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    IconButton(
                        onClick = { onCopy(if (item.type == "ACCOUNT") "پسورد" else "یادداشت", item.secretOrBody) },
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
                    color = Color(0xFF9CA3AF),
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
        containerColor = Color(0xFF121724),
        titleContentColor = Color.White,
        title = {
            Text(
                text = if (initialItem != null) "ویرایش آیتم" else "افزودن آیتم جدید",
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
                        label = { Text("اکانت") }
                    )
                    FilterChip(
                        selected = selectedType == "NOTE",
                        onClick = { selectedType = "NOTE" },
                        label = { Text("یادداشت") }
                    )
                }

                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("عنوان (مثلاً Gmail اصلی، Steam، یادداشت)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                if (selectedType == "ACCOUNT") {
                    OutlinedTextField(
                        value = emailOrUser,
                        onValueChange = { emailOrUser = it },
                        label = { Text("جیمیل / یوزرنیم / آیدی") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    OutlinedTextField(
                        value = secretOrBody,
                        onValueChange = { secretOrBody = it },
                        label = { Text("پسورد") },
                        singleLine = true,
                        visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                Icon(
                                    imageVector = if (passwordVisible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    OutlinedTextField(
                        value = secretOrBody,
                        onValueChange = { secretOrBody = it },
                        label = { Text("متن یادداشت امن") },
                        minLines = 3,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                OutlinedTextField(
                    value = extraNote,
                    onValueChange = { extraNote = it },
                    label = { Text("توضیح اضافه (اختیاری)") },
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
                                title = title.ifBlank { if (selectedType == "ACCOUNT") "اکانت بدون عنوان" else "یادداشت" },
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
                Text("ذخیره امن", fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("لغو", color = Color(0xFF9CA3AF))
            }
        }
    )
}
