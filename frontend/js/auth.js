const API = "/api/auth";

async function sendRequest(endpoint, payload) {
  const response = await fetch(`${API}/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || "Something went wrong.");
  return data;
}

function showMessage(element, message, success = false) {
  element.textContent = message;
  element.classList.toggle("success", success);
}

const loginForm = document.getElementById("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const button = loginForm.querySelector("button");
    const message = document.getElementById("formMessage");
    button.disabled = true;
    showMessage(message, "Logging in...");
    try {
      const result = await sendRequest("login", {
        email: loginForm.email.value,
        password: loginForm.password.value
      });
      showMessage(message, result.message, true);
      window.location.href = "/portfolio";
    } catch (error) {
      showMessage(message, error.message);
    } finally {
      button.disabled = false;
    }
  });
}

const signupForm = document.getElementById("signupForm");
if (signupForm) {
  signupForm.addEventListener("submit", async event => {
    event.preventDefault();
    const button = signupForm.querySelector("button");
    const message = document.getElementById("formMessage");
    const password = signupForm.password.value;
    const confirmPassword = signupForm.confirmPassword.value;
    if (password !== confirmPassword) {
      showMessage(message, "Passwords do not match.");
      return;
    }
    button.disabled = true;
    showMessage(message, "Creating your account...");
    try {
      const result = await sendRequest("register", {
        name: signupForm.name.value,
        email: signupForm.email.value,
        password
      });
      showMessage(message, result.message, true);
      window.location.href = "/portfolio";
    } catch (error) {
      showMessage(message, error.message);
    } finally {
      button.disabled = false;
    }
  });
}
