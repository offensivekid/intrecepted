// Modern Forum - Complete Frontend Application
console.log('🚀 Modern Forum initialized');

// ============= TRANSLATIONS =============

const translations = {
    ru: {
        // Navigation
        home: 'Главная',
        popular: 'Популярное',
        private: 'Приватное',
        admin: 'Панель',
        keys: 'Ключи доступа',
        
        // Auth
        login: 'Вход',
        signup: 'Регистрация',
        logout: 'Выход',
        profile: 'Профиль',
        settings: 'Настройки',
        
        // Threads -> Темы
        latest_threads: 'Последние темы',
        discover: 'Узнай что происходит в сообществе',
        create_thread: 'Создать тему',
        loading_threads: 'Загрузка тем...',
        no_threads: 'Тем пока нет',
        be_first: 'Будь первым, начни разговор!',
        
        // Filters
        all: 'Все',
        popular_filter: 'Популярное',
        recent: 'Свежее',
        
        // Forms
        username: 'Имя пользователя',
        password: 'Пароль',
        email: 'Email',
        access_key: 'Ключ доступа',
        optional: '(опционально)',
        access_key_help: 'Введи ключ доступа для разблокировки приватных тем',
        
        // Modals
        welcome_back: 'С возвращением',
        create_account: 'Создать аккаунт',
        new_thread: 'Создать новую тему',
        thread_title: 'Заголовок темы',
        description: 'Описание',
        
        // Buttons
        submit: 'Войти',
        create: 'Создать аккаунт',
        create_btn: 'Создать тему',
        
        // Messages
        no_account: 'Нет аккаунта?',
        register_link: 'Зарегистрируйся',
        have_account: 'Уже есть аккаунт?',
        login_link: 'Войди',
        
        // Stats
        threads: 'Тем',
        users: 'Юзеров',
        replies: 'ответов',
        views: 'просмотров',
        
        // Admin
        admin_panel: 'Админ-панель',
        manage_forum: 'Управление форумом',
        total_keys: 'Всего ключей',
        active_keys: 'Активных',
        used_keys: 'Использовано',
        generate_keys: 'Генерация ключей',
        keys_list: 'Список ключей',
        generate_btn: 'Сгенерировать',
        loading_keys: 'Загрузка ключей...',
        
        // Notifications
        welcome: 'С возвращением!',
        account_created: 'Аккаунт создан! Теперь войди.',
        thread_created: 'Тема создана!',
        reply_posted: 'Ответ отправлен!',
        keys_generated: 'ключей сгенерировано!',
        
        // Search
        search_placeholder: 'Поиск тем...',
        no_results: 'Ничего не найдено',
        
        // Other
        back: 'Назад',
        reply: 'Ответ',
        post_reply: 'Отправить ответ',
        write_reply: 'Напиши свой ответ...',
        login_to_reply: 'Войди, чтобы ответить',
        no_replies: 'Ответов пока нет. Будь первым!'
    },
    en: {
        // Navigation
        home: 'Home',
        popular: 'Popular',
        private: 'Private',
        admin: 'Dashboard',
        keys: 'Access Keys',
        
        // Auth
        login: 'Login',
        signup: 'Sign Up',
        logout: 'Logout',
        profile: 'Profile',
        settings: 'Settings',
        
        // Threads
        latest_threads: 'Latest Threads',
        discover: 'Discover what\'s happening in the community',
        create_thread: 'Create Thread',
        loading_threads: 'Loading threads...',
        no_threads: 'No threads yet',
        be_first: 'Be the first to start a conversation!',
        
        // Filters
        all: 'All',
        popular_filter: 'Popular',
        recent: 'Recent',
        
        // Forms
        username: 'Username',
        password: 'Password',
        email: 'Email',
        access_key: 'Access Key',
        optional: '(optional)',
        access_key_help: 'Enter access key to unlock private threads',
        
        // Modals
        welcome_back: 'Welcome Back',
        create_account: 'Create Account',
        new_thread: 'Create New Thread',
        thread_title: 'Thread Title',
        description: 'Description',
        
        // Buttons
        submit: 'Login',
        create: 'Create Account',
        create_btn: 'Create Thread',
        
        // Messages
        no_account: 'Don\'t have an account?',
        register_link: 'Sign up',
        have_account: 'Already have an account?',
        login_link: 'Login',
        
        // Stats
        threads: 'Threads',
        users: 'Users',
        replies: 'replies',
        views: 'views',
        
        // Admin
        admin_panel: 'Admin Panel',
        manage_forum: 'Manage your forum',
        total_keys: 'Total Keys',
        active_keys: 'Active',
        used_keys: 'Used',
        generate_keys: 'Generate Keys',
        keys_list: 'Keys List',
        generate_btn: 'Generate',
        loading_keys: 'Loading keys...',
        
        // Notifications
        welcome: 'Welcome back!',
        account_created: 'Account created! Please login.',
        thread_created: 'Thread created!',
        reply_posted: 'Reply posted!',
        keys_generated: 'keys generated!',
        
        // Search
        search_placeholder: 'Search threads...',
        no_results: 'No results found',
        
        // Other
        back: 'Back',
        reply: 'Reply',
        post_reply: 'Post Reply',
        write_reply: 'Write your reply...',
        login_to_reply: 'Login to reply',
        no_replies: 'No replies yet. Be the first!'
    }
};

let currentLang = localStorage.getItem('lang') || 'ru';

function t(key) {
    return translations[currentLang][key] || key;
}

function toggleLanguage() {
    currentLang = currentLang === 'ru' ? 'en' : 'ru';
    localStorage.setItem('lang', currentLang);
    document.getElementById('langText').textContent = currentLang === 'ru' ? 'EN' : 'RU';
    updateUILanguage();
}

function updateUILanguage() {
    // Update all translatable elements
    const lang = currentLang;
    
    // Main heading
    const heading = document.querySelector('.section-heading');
    if (heading) heading.textContent = t('latest_threads');
    
    const subheading = document.querySelector('.section-subheading');
    if (subheading) subheading.textContent = t('discover');
    
    // Search
    const search = document.getElementById('globalSearch');
    if (search) search.placeholder = t('search_placeholder');
    
    // Buttons
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) loginBtn.textContent = t('login');
    
    const signupBtn = document.getElementById('signupBtn');
    if (signupBtn) signupBtn.textContent = t('signup');
    
    const createBtn = document.getElementById('createThreadBtn');
    if (createBtn) createBtn.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
        </svg>
        ${t('create_thread')}
    `;
    
    // Sidebar menu items
    const menuItems = document.querySelectorAll('.menu-item span');
    if (menuItems[0]) menuItems[0].textContent = t('home');
    if (menuItems[1]) menuItems[1].textContent = t('popular');
    
    // Stats
    const statsLabel = document.querySelector('.stat-label');
    if (statsLabel) statsLabel.textContent = t('threads');
    
    // Section titles
    const navTitle = document.querySelector('.section-title');
    if (navTitle) navTitle.textContent = lang === 'ru' ? 'Навигация' : 'Navigation';
    
    const statsTitle = document.querySelectorAll('.section-title')[1];
    if (statsTitle) statsTitle.textContent = lang === 'ru' ? 'Статистика' : 'Statistics';
    
    // Filter tabs
    const filterTabs = document.querySelectorAll('.filter-tab');
    if (filterTabs[0]) filterTabs[0].textContent = t('all');
    if (filterTabs[1]) filterTabs[1].textContent = t('popular_filter');
    if (filterTabs[2]) filterTabs[2].textContent = t('recent');
    
    // Loading text
    const loadingSpinner = document.querySelector('.loading-spinner span');
    if (loadingSpinner) loadingSpinner.textContent = t('loading_threads');
    
    // Reload threads to update text
    if (state.threads.length > 0) {
        renderThreads();
    }
}

// Global State
const state = {
    user: null,
    threads: [],
    currentThread: null,
    currentSection: 'home',
    filters: {
        active: 'all'
    }
};

// ============= UTILITY FUNCTIONS =============

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
}

function getInitials(name) {
    return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2) || name.slice(0, 2).toUpperCase();
}

// ============= API FUNCTIONS =============

async function apiCall(endpoint, options = {}) {
    const res = await fetch(`/api${endpoint}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        credentials: 'include'
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
}

// ============= AUTHENTICATION =============

async function login(e) {
    e.preventDefault();
    try {
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;
        const accessKey = document.getElementById('loginKey').value.trim();
        
        const data = await apiCall('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password, accessKey })
        });
        
        state.user = data.user;
        closeModal('login');
        showToast(t('welcome'), 'success');
        updateUI();
        await loadThreads();
        
        if (state.user.isAdmin) {
            await loadAdminData();
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function signup(e) {
    e.preventDefault();
    try {
        const username = document.getElementById('signupUsername').value.trim();
        const email = document.getElementById('signupEmail').value.trim();
        const password = document.getElementById('signupPassword').value;
        const registrationKey = document.getElementById('signupKey').value.trim();
        
        await apiCall('/register', {
            method: 'POST',
            body: JSON.stringify({ username, email, password, registrationKey })
        });
        
        showToast(t('account_created'), 'success');
        closeModal('signup');
        showModal('login');
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function logout() {
    try {
        await apiCall('/logout', { method: 'POST' });
        state.user = null;
        location.reload();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function checkAuth() {
    try {
        const data = await apiCall('/me');
        state.user = data;
        updateUI();
        if (state.user.isAdmin) {
            await loadAdminData();
        }
    } catch (err) {
        // Not authenticated
        console.log('Not authenticated');
    }
}

// ============= THREADS =============

async function loadThreads() {
    try {
        state.threads = await apiCall('/threads');
        renderThreads();
        updateStats();
    } catch (err) {
        console.error('Failed to load threads:', err);
        showToast('Не удалось загрузить треды', 'error');
    }
}

function renderThreads() {
    const container = document.getElementById('publicThreads');
    const threads = state.threads.filter(t => !t.is_private);
    
    if (threads.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
                    </svg>
                </div>
                <div class="empty-title">${t('no_threads')}</div>
                <div class="empty-message">${t('be_first')}</div>
            </div>
        `;
        return;
    }
    
    container.innerHTML = threads.map((thread, index) => `
        <div class="thread-card" onclick="viewThread(${thread.id})" style="animation-delay: ${index * 0.1}s;">
            <div class="thread-header">
                <div class="thread-avatar">${getInitials(thread.author_username)}</div>
                <div class="thread-meta">
                    <div class="thread-author">
                        ${escapeHtml(thread.author_username)}
                        ${thread.is_private ? '<span class="thread-badge">PRIVATE</span>' : ''}
                    </div>
                    <div class="thread-time">${formatTime(thread.created_at)}</div>
                </div>
            </div>
            <h3 class="thread-title">${escapeHtml(thread.title)}</h3>
            <p class="thread-preview">${escapeHtml(thread.body.substring(0, 150))}${thread.body.length > 150 ? '...' : ''}</p>
            <div class="thread-footer">
                <div class="thread-stat">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>
                    </svg>
                    ${thread.reply_count || 0} ${t('replies')}
                </div>
                <div class="thread-stat">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                        <circle cx="12" cy="12" r="3"/>
                    </svg>
                    ${thread.views || 0} ${t('views')}
                </div>
            </div>
        </div>
    `).join('');
}

async function viewThread(threadId) {
    try {
        const thread = await apiCall(`/threads/${threadId}`);
        state.currentThread = thread;
        renderThreadDetail(thread);
        
        // Switch to thread view
        document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
        document.getElementById('threadSection').classList.add('active');
        
        // Increment view count
        await apiCall(`/threads/${threadId}/view`, { method: 'POST' });
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function renderThreadDetail(thread) {
    const container = document.getElementById('threadDetail');
    
    container.innerHTML = `
        <div class="thread-detail-container">
            <div class="thread-detail-header">
                <button class="back-button" onclick="backToHome()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M19 12H5M12 19l-7-7 7-7"/>
                    </svg>
                    Назад
                </button>
                <div class="thread-header">
                    <div class="thread-avatar" style="width: 48px; height: 48px; font-size: 18px;">
                        ${getInitials(thread.author_username)}
                    </div>
                    <div class="thread-meta">
                        <div class="thread-author" style="font-size: 16px;">
                            ${escapeHtml(thread.author_username)}
                            ${thread.is_private ? '<span class="thread-badge">PRIVATE</span>' : ''}
                        </div>
                        <div class="thread-time">${formatTime(thread.created_at)}</div>
                    </div>
                </div>
                <h1 class="thread-title" style="font-size: 28px; margin-top: 20px;">
                    ${escapeHtml(thread.title)}
                </h1>
            </div>
            
            <div class="thread-detail-body">
                <div class="thread-content">
                    ${escapeHtml(thread.body).replace(/\n/g, '<br>')}
                </div>
            </div>
            
            <div class="replies-section">
                <h3 class="replies-header">
                    ${thread.replies.length} ${thread.replies.length === 1 ? 'Ответ' : 'Ответов'}
                </h3>
                
                ${thread.replies.length > 0 ? thread.replies.map(reply => `
                    <div class="reply-card">
                        <div class="thread-header" style="margin-bottom: 12px;">
                            <div class="thread-avatar" style="width: 36px; height: 36px; font-size: 14px;">
                                ${getInitials(reply.author_username)}
                            </div>
                            <div class="thread-meta">
                                <div class="thread-author" style="font-size: 14px;">
                                    ${escapeHtml(reply.author_username)}
                                </div>
                                <div class="thread-time" style="font-size: 12px;">
                                    ${formatTime(reply.created_at)}
                                </div>
                            </div>
                        </div>
                        <div style="color: var(--text-secondary); font-size: 14px; line-height: 1.6;">
                            ${escapeHtml(reply.text).replace(/\n/g, '<br>')}
                        </div>
                    </div>
                `).join('') : '<div class="empty-state" style="padding: 40px 20px;"><div class="empty-message">Ответов пока нет. Будь первым!</div></div>'}
                
                ${state.user ? `
                    <div class="reply-form">
                        <form onsubmit="postReply(event, ${thread.id})">
                            <textarea placeholder="Напиши свой ответ..." id="replyText" required minlength="1"></textarea>
                            <button type="submit" class="btn-primary" style="margin-top: 12px;">Отправить ответ</button>
                        </form>
                    </div>
                ` : `
                    <div class="empty-state" style="padding: 30px 20px;">
                        <div class="empty-message">
                            <a href="#" onclick="showModal('login'); return false;" style="color: var(--accent-primary); text-decoration: none; font-weight: 600;">Войди</a>, чтобы ответить
                        </div>
                    </div>
                `}
            </div>
        </div>
    `;
}

async function postReply(e, threadId) {
    e.preventDefault();
    try {
        const text = document.getElementById('replyText').value.trim();
        if (!text) return;
        
        await apiCall(`/threads/${threadId}/replies`, {
            method: 'POST',
            body: JSON.stringify({ text })
        });
        
        showToast('Ответ отправлен!', 'success');
        await viewThread(threadId);
    } catch (err) {
        showToast(err.message, 'error');
    }
}

async function createThread(e) {
    e.preventDefault();
    try {
        const title = document.getElementById('threadTitle').value.trim();
        const body = document.getElementById('threadBody').value.trim();
        const isPrivate = document.getElementById('isPrivate')?.checked || false;
        
        await apiCall('/threads', {
            method: 'POST',
            body: JSON.stringify({ title, body, isPrivate })
        });
        
        showToast('Тред создан!', 'success');
        closeModal('createThread');
        await loadThreads();
        
        // Clear form
        document.getElementById('threadTitle').value = '';
        document.getElementById('threadBody').value = '';
        if (document.getElementById('isPrivate')) {
            document.getElementById('isPrivate').checked = false;
        }
    } catch (err) {
        showToast(err.message, 'error');
    }
}

function backToHome() {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.getElementById('homeSection').classList.add('active');
    state.currentThread = null;
}

// ============= ADMIN FUNCTIONS =============

async function loadAdminData() {
    try {
        const keys = await apiCall('/admin/keys');
        renderAdminStats(keys);
        renderKeysList(keys);
    } catch (err) {
        console.error('Failed to load admin data:', err);
    }
}

function renderAdminStats(keys) {
    const total = keys.length;
    const active = keys.filter(k => k.is_active && !k.used_by).length;
    const used = keys.filter(k => k.used_by).length;
    
    document.getElementById('adminTotalKeys').textContent = total;
    document.getElementById('adminActiveKeys').textContent = active;
    document.getElementById('adminUsedKeys').textContent = used;
}

function renderKeysList(keys) {
    const container = document.getElementById('keysList');
    
    if (keys.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-message">Ключей пока не создано</div></div>';
        return;
    }
    
    container.innerHTML = keys.map(key => `
        <div class="key-item">
            <div>
                <div class="key-code">${escapeHtml(key.key_code)}</div>
                <div style="font-size: 12px; color: var(--text-tertiary); margin-top: 4px;">
                    Created ${formatTime(key.created_at)}
                </div>
            </div>
            <div class="key-status">
                <div class="status-dot ${key.used_by ? 'used' : 'active'}"></div>
                <span style="font-size: 13px; color: var(--text-secondary);">
                    ${key.used_by ? `Использован: ${escapeHtml(key.used_by_username)}` : 'Активен'}
                </span>
            </div>
        </div>
    `).join('');
}

async function generateKeys() {
    try {
        const count = parseInt(document.getElementById('keyCount').value);
        if (!count || count < 1 || count > 50) {
            showToast('Введи число от 1 до 50', 'error');
            return;
        }
        
        const data = await apiCall('/admin/keys/generate', {
            method: 'POST',
            body: JSON.stringify({ count })
        });
        
        showToast(`${data.keys.length} ${data.keys.length === 1 ? 'ключ' : 'ключей'} сгенерировано!`, 'success');
        await loadAdminData();
        document.getElementById('keyCount').value = '1';
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// ============= UI FUNCTIONS =============

function updateUI() {
    const loginBtn = document.getElementById('loginBtn');
    const signupBtn = document.getElementById('signupBtn');
    const userMenu = document.getElementById('userMenu');
    const createBtn = document.getElementById('createThreadBtn');
    const privateNav = document.getElementById('privateNav');
    const adminSection = document.getElementById('adminSection');
    
    if (state.user) {
        // Hide login/signup, show user menu
        loginBtn.style.display = 'none';
        signupBtn.style.display = 'none';
        userMenu.style.display = 'block';
        createBtn.style.display = 'flex';
        
        // Update user info
        const initials = getInitials(state.user.username);
        document.getElementById('avatarText').textContent = initials;
        document.getElementById('dropdownUsername').textContent = state.user.username;
        
        if (state.user.isAdmin) {
            document.getElementById('dropdownRole').textContent = 'Админ';
            adminSection.style.display = 'block';
            if (document.getElementById('privateCheckbox')) {
                document.getElementById('privateCheckbox').style.display = 'block';
            }
        } else if (state.user.hasPrivateAccess) {
            document.getElementById('dropdownRole').textContent = 'PRO участник';
        }
        
        // Show private nav if user has access
        if (state.user.hasPrivateAccess || state.user.isAdmin) {
            privateNav.style.display = 'flex';
        }
    } else {
        loginBtn.style.display = 'block';
        signupBtn.style.display = 'block';
        userMenu.style.display = 'none';
        createBtn.style.display = 'none';
        privateNav.style.display = 'none';
        adminSection.style.display = 'none';
    }
}

function updateStats() {
    document.getElementById('totalThreads').textContent = state.threads.length;
}

function showModal(modalId) {
    const modal = document.getElementById(modalId + 'Modal');
    if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId + 'Modal');
    if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
        error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${icons[type]}</div>
        <div class="toast-content">
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function showProfile() {
    showToast('Профиль скоро будет!', 'info');
}

function showSettings() {
    showToast('Настройки скоро будут!', 'info');
}

// ============= SEARCH =============

let searchTimeout;
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('globalSearch');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                const query = e.target.value.toLowerCase().trim();
                if (!query) {
                    renderThreads();
                    return;
                }
                
                const filtered = state.threads.filter(t => 
                    t.title.toLowerCase().includes(query) || 
                    t.body.toLowerCase().includes(query) ||
                    t.author_username.toLowerCase().includes(query)
                );
                
                const container = document.getElementById('publicThreads');
                if (filtered.length === 0) {
                    container.innerHTML = '<div class="empty-state"><div class="empty-message">Ничего не найдено</div></div>';
                } else {
                    state.threads = filtered;
                    renderThreads();
                }
            }, 300);
        });
    }
});

// ============= NAVIGATION =============

document.addEventListener('DOMContentLoaded', () => {
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            
            // Update active menu item
            menuItems.forEach(mi => mi.classList.remove('active'));
            item.classList.add('active');
            
            // Show corresponding section
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            
            if (section === 'home') {
                document.getElementById('homeSection').classList.add('active');
            } else if (section === 'admin') {
                document.getElementById('adminDashboard').classList.add('active');
            }
        });
    });
});

// ============= INITIALIZATION =============

async function init() {
    console.log('Initializing application...');
    
    // Set initial language
    document.getElementById('langText').textContent = currentLang === 'ru' ? 'EN' : 'RU';
    updateUILanguage();
    
    try {
        // Check authentication
        await checkAuth();
        
        // Load threads
        await loadThreads();
    } catch (err) {
        console.error('Initialization error:', err);
        showToast(currentLang === 'ru' ? 'Ошибка загрузки. Перезагрузи страницу.' : 'Loading error. Reload the page.', 'error');
    } finally {
        // Hide loading screen
        const loadingScreen = document.getElementById('loadingScreen');
        if (loadingScreen) {
            setTimeout(() => {
                loadingScreen.classList.add('hidden');
                setTimeout(() => loadingScreen.remove(), 500);
            }, 500);
        }
    }
}

// Start the application
document.addEventListener('DOMContentLoaded', init);

// Handle filter tabs
document.addEventListener('DOMContentLoaded', () => {
    const filterTabs = document.querySelectorAll('.filter-tab');
    filterTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            filterTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            const filter = tab.dataset.filter;
            state.filters.active = filter;
            
            // Apply filter logic here
            renderThreads();
        });
    });
});
