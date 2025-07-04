function showNotification(message, type) {
    const icon = document.getElementById('notificationIcon');
    const msg = document.getElementById('notificationMessage');
    const box = document.getElementById('notification');

    icon.textContent = '';
    msg.textContent = '';
    box.className = 'notification-bar show';
    icon.className = 'notification-icon';

    box.classList.remove('error', 'success');
    if (type === 'success') {
        icon.textContent = '✔';
        box.classList.add('success');
    } else {
        icon.textContent = '✖';
        box.classList.add('error');
    }

    msg.textContent = message;
    box.classList.remove('hidden');

    setTimeout(() => {
        box.classList.remove('show');
        setTimeout(() => {
            box.classList.add('hidden');
            box.classList.remove(type);
        }, 300);
    }, 3000);
}
