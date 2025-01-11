document.addEventListener("DOMContentLoaded", function () {
    const loginElement = document.getElementById("login");
    if (!loginElement) return;

    const template = document.getElementById("mfa_login_oauth2");
    if (!template) return;

    const providerName = template.dataset.title;

    if (providerName === "redirect") {
        window.location.href = "/plugin/oauth2/login";
        return;
    }

    const content = document.createElement("div");
    content.innerHTML = template.innerHTML;
    const providerElement = content.querySelector("#provider");
    if (providerElement) {
        providerElement.textContent = providerName;
    }

    loginElement.appendChild(content);
});
