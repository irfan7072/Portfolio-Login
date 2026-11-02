document.getElementById("year").textContent = new Date().getFullYear();

async function updateAuthNavigation() {
  const container = document.getElementById("authNav");
  try {
    const response = await fetch("/api/auth/me", { credentials: "same-origin" });
    const data = await response.json();
    if (data.user) {
      const name = document.createElement("span");
      name.textContent = `Hi, ${data.user.name}`;
      const logout = document.createElement("button");
      logout.className = "nav-logout";
      logout.textContent = "Logout";
      logout.addEventListener("click", async () => {
        await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
        window.location.href = "/";
      });
      container.replaceChildren(name, logout);
    }
  } catch (error) {
    console.error("Could not check login status:", error);
  }
}
updateAuthNavigation();
