document.addEventListener('DOMContentLoaded', function() {
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
  
  var form = document.getElementById('regForm');
  var usernameInput = document.getElementById('username');
  var welcomeElement = document.getElementById('welcome');
  var emailInput = document.getElementById('email');
  var passInput = document.getElementById('password');

  if (!form || !usernameInput || !welcomeElement || !emailInput || !passInput) {
    console.error('Один из элементов не найден: regForm, username, email, welcome, passInput');
    return;
  }

  // Валидация имени пользователя
  form.addEventListener('submit', function(e) {
    var username = usernameInput.value.trim();
    var email = emailInput.value.trim();
	var passw = passInput.value.trim();

    // Проверка имени
    if (username.length < 3) {
      alert('Имя должно быть не меньше 3 символов');
      usernameInput.focus();
      e.preventDefault();
      return;
    }

    // Проверка email перед отправкой
    if (!validateEmailFinal(email)) {
	  alert('Формат ввода почтового адреса name@domain.zone');
      e.preventDefault();
      emailInput.focus();
      return;
    }
	
	// Проверка длины пароля
    if (passw.length < 8) {
      alert('Пароль должен быть не меньше 8 символов');
      passInput.focus();
      e.preventDefault();
      return;
    }

	// Защита но вероятна DOM XSS атака
     welcomeElement.textContent = "Привет, " + escapeHtml(username) + "!";
	// welcomeElement.innerHTML = "Привет, " + escapeHtml(username) + "!";
	// welcomeElement.innerHTML = "Привет, " + username + "!";
  });

  usernameInput.addEventListener('input', function() {
    welcomeElement.textContent = '';
  });

  // Валидация email
  function validateEmail() {
    var value = emailInput.value.trim();
    // Исправленное регулярное выражение: \\. вместо \.
    var emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (value && !emailRegex.test(value)) {
      emailInput.setCustomValidity('Введите корректный email (например, user@example.com)');
    } else {
      emailInput.setCustomValidity(''); // Сбрасываем ошибку
    }
    updateEmailValidationUI(value, emailRegex);
  }

  function validateEmailFinal(value) {
    var emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return !value || emailRegex.test(value);
  }

  function updateEmailValidationUI(value, regex) {
    if (value && !regex.test(value)) {
      emailInput.classList.add('error');
      emailInput.classList.remove('valid');
    } else if (value) {
      emailInput.classList.add('valid');
      emailInput.classList.remove('error');
    } else {
      emailInput.classList.remove('error', 'valid');
    }
  }

  // Вызываем валидацию при потере фокуса и вводе
  emailInput.addEventListener('blur', validateEmail);
  emailInput.addEventListener('input', validateEmail);

  // Проверяем email при загрузке (если уже что-то введено)
  validateEmail();
});
