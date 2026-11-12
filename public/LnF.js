
// ======================================
// AUTHENTICATION: REGISTER + LOGIN
// ======================================

const authScreen = document.getElementById("authScreen");
const appShell = document.getElementById("appShell");

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const otpForm = document.getElementById("otpForm");

const authTitle = document.getElementById("authTitle");
const authSubtitle = document.getElementById("authSubtitle");

const authMessage = document.getElementById("authMessage");
const otpHint = document.getElementById("otpHint");

const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const verifyOtpBtn = document.getElementById("verifyOtpBtn");

let pendingEmail = "";

// Display messages
function showAuthMessage(message, success = false) {
  authMessage.textContent = message;
  authMessage.classList.toggle("success", success);
}

// API helper
async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(options.body
        ? { "Content-Type": "application/json" }
        : {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.message || "Something went wrong.");
  }

  return data;
}

// Show login form
function showLogin() {
  loginForm.hidden = false;
  registerForm.hidden = true;
  otpForm.hidden = true;

  authTitle.textContent = "Welcome back";
  authSubtitle.textContent =
    "Log in to access your Lost & Found account.";

  showAuthMessage("");
}

// Show registration form
function showRegister() {
  loginForm.hidden = true;
  registerForm.hidden = false;
  otpForm.hidden = true;

  authTitle.textContent = "Create account";
  authSubtitle.textContent =
    "Register to report and find lost items.";

  showAuthMessage("");
}

// Switch between login and register
document.getElementById("showRegisterBtn")
  .addEventListener("click", showRegister);

document.getElementById("showLoginBtn")
  .addEventListener("click", showLogin);


// ======================================
// REGISTER: REQUEST OTP
// ======================================

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const firstName =
    document.getElementById("firstName").value.trim();

  const lastName =
    document.getElementById("lastName").value.trim();

  const email =
    document.getElementById("registerEmail").value.trim().toLowerCase();

  const phone =
    document.getElementById("phone").value.trim();

  const password =
    document.getElementById("registerPassword").value;

  const confirmPassword =
    document.getElementById("confirmPassword").value;

  if (password !== confirmPassword) {
    return showAuthMessage("Passwords do not match.");
  }

  if (password.length < 8 || password.length > 72) {
    return showAuthMessage(
      "Password must contain 8 to 72 characters."
    );
  }

  registerBtn.disabled = true;
  showAuthMessage("");

  try {
    const result = await api("/api/auth/register/request-otp", {
      method: "POST",
      body: JSON.stringify({
        firstName,
        lastName,
        email,
        phone,
        password
      })
    });

    pendingEmail = email;

    registerForm.hidden = true;
    otpForm.hidden = false;

    authTitle.textContent = "Verify your email";
    authSubtitle.textContent =
      "One last step before creating your account.";

    otpHint.textContent =
      `We sent a 6-digit code to ${email}. It expires in 5 minutes.`;

    showAuthMessage(result.message, true);

    document.getElementById("otpCode").focus();

  } catch (error) {
    showAuthMessage(error.message);
  } finally {
    registerBtn.disabled = false;
  }
});


// ======================================
// REGISTER: VERIFY OTP
// ======================================

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const otp = document.getElementById("otpCode").value.trim();

  if (!/^\d{6}$/.test(otp)) {
    return showAuthMessage("Enter the 6-digit OTP.");
  }

  verifyOtpBtn.disabled = true;
  showAuthMessage("");

  try {
    const result = await api("/api/auth/register/verify-otp", {
      method: "POST",
      body: JSON.stringify({
        email: pendingEmail,
        otp
      })
    });

    otpForm.hidden = true;
    authScreen.hidden = true;
    appShell.hidden = false;

    document.getElementById("otpCode").value = "";

    await loadItems();

    alert(`Welcome, ${result.user.firstName}! Your account is ready.`);

  } catch (error) {
    showAuthMessage(error.message);
  } finally {
    verifyOtpBtn.disabled = false;
  }
});


// Back to registration
document.getElementById("backToRegisterBtn")
  .addEventListener("click", () => {
    otpForm.hidden = true;
    registerForm.hidden = false;

    document.getElementById("otpCode").value = "";

    authTitle.textContent = "Create account";
    authSubtitle.textContent =
      "Register to report and find lost items.";

    showAuthMessage("");
  });


// ======================================
// LOGIN: EMAIL + PASSWORD
// ======================================

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email =
    document.getElementById("loginEmail").value.trim().toLowerCase();

  const password =
    document.getElementById("loginPassword").value;

  loginBtn.disabled = true;
  showAuthMessage("");

  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email,
        password
      })
    });

    authScreen.hidden = true;
    appShell.hidden = false;

    document.getElementById("loginPassword").value = "";

    await loadItems();

    console.log(`Logged in as ${result.user.firstName}`);

  } catch (error) {
    showAuthMessage(error.message);
  } finally {
    loginBtn.disabled = false;
  }
});


// ======================================
// CHECK EXISTING LOGIN SESSION
// ======================================

async function checkSession() {
  try {
    await api("/api/auth/me");

    authScreen.hidden = true;
    appShell.hidden = false;

    await loadItems();

  } catch {
    authScreen.hidden = false;
    appShell.hidden = true;

    showLogin();
  }
}


// ======================================
// LOGOUT
// ======================================

document.getElementById("logoutBtn")
  .addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", {
        method: "POST"
      });

      appShell.hidden = true;
      authScreen.hidden = false;

      loginForm.reset();
      registerForm.reset();
      otpForm.reset();

      showLogin();

    } catch (error) {
      alert(error.message);
    }
  });



// ======================================
// LOST & FOUND: MONGODB API
// ======================================

const form = document.getElementById("itemForm");
const list = document.getElementById("items");
const search = document.getElementById("search");

const chips = document.querySelectorAll(".chip");

const dateInput = document.getElementById("date");
const photoInput = document.getElementById("photo");

const preview = document.getElementById("preview");
const previewImg = document.getElementById("previewImg");
const removePhoto = document.getElementById("removePhoto");

let currentImage = "";
let currentFilter = "all";
let items = [];

if (dateInput) {
  dateInput.valueAsDate = new Date();
}


// Resize uploaded images before sending them to the server
function resizeImage(file, maxSize = 700) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onerror = reject;

    reader.onload = () => {
      const img = new Image();

      img.onerror = reject;

      img.onload = () => {
        const scale = Math.min(
          1,
          maxSize / Math.max(img.width, img.height)
        );

        const canvas = document.createElement("canvas");

        canvas.width = Math.round(img.width * scale);
        canvas.height = Math.round(img.height * scale);

        canvas.getContext("2d").drawImage(
          img,
          0,
          0,
          canvas.width,
          canvas.height
        );

        resolve(canvas.toDataURL("image/jpeg", 0.72));
      };

      img.src = reader.result;
    };

    reader.readAsDataURL(file);
  });
}


// Clear selected photo
function clearPhoto() {
  currentImage = "";
  photoInput.value = "";

  preview.hidden = true;
  previewImg.removeAttribute("src");
}


// Photo selection
photoInput.addEventListener("change", async () => {
  const file = photoInput.files[0];

  if (!file) {
    return clearPhoto();
  }

  if (!file.type.startsWith("image/")) {
    alert("Please choose an image file.");
    return clearPhoto();
  }

  if (file.size > 5 * 1024 * 1024) {
    alert("Please choose an image smaller than 5 MB.");
    return clearPhoto();
  }

  try {
    currentImage = await resizeImage(file);

    previewImg.src = currentImage;
    preview.hidden = false;

  } catch {
    alert("That image couldn't be read. Try a different file.");
    clearPhoto();
  }
});

removePhoto.addEventListener("click", clearPhoto);


// Escape HTML to prevent user-entered text from being interpreted as markup
function escapeHTML(value) {
  const div = document.createElement("div");

  div.textContent = String(value ?? "");

  return div.innerHTML;
}


// Display items
function render() {
  const q = search.value.trim().toLowerCase();

  const visible = items.filter(item =>
    (currentFilter === "all" || item.type === currentFilter) &&
    (
      `${item.name} ${item.location} ${item.desc || ""}`
        .toLowerCase()
        .includes(q)
    )
  );

  if (!visible.length) {
    list.innerHTML = `
      <div class="empty">
        No items match. Post one using the form.
      </div>
    `;
    return;
  }

  list.innerHTML = visible.map(item => `
    <article class="item ${item.type} ${item.resolved ? "resolved" : ""}">

      <span class="tag ${item.type}">
        ${item.type === "lost" ? "Lost" : "Found"}
      </span>

      ${
        item.image
          ? `<img class="photo"
              src="${item.image}"
              alt="Photo of ${escapeHTML(item.name)}">`
          : ""
      }

      <h3>${escapeHTML(item.name)}</h3>

      <p>
        ${escapeHTML(item.location)}
        on ${escapeHTML(item.date)}
      </p>

      ${
        item.desc
          ? `<p>${escapeHTML(item.desc)}</p>`
          : ""
      }

      <p class="contact">
        Contact: ${escapeHTML(item.contact)}
      </p>

      <div class="item-actions">

        <button
          data-action="resolve"
          data-id="${item._id}">
          ${item.resolved ? "Reopen" : "Mark returned"}
        </button>

        <button
          data-action="delete"
          data-id="${item._id}">
          Delete
        </button>

      </div>
    </article>
  `).join("");
}


// Load items from MongoDB through the backend
async function loadItems() {
  try {
    const data = await api("/api/items");

    items = data.items || [];

    render();

  } catch (error) {
    list.innerHTML = `
      <div class="empty">
        ${escapeHTML(error.message)}
      </div>
    `;
  }
}


// Add a new lost or found item
form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const submitButton =
    form.querySelector('button[type="submit"]');

  submitButton.disabled = true;

  try {
    const payload = {
      type: form.elements.type.value,
      name: form.elements.name.value.trim(),
      location: form.elements.location.value.trim(),
      date: form.elements.date.value,
      contact: form.elements.contact.value.trim(),
      desc: form.elements.desc.value.trim(),
      image: currentImage
    };

    await api("/api/items", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    form.reset();

    clearPhoto();

    dateInput.valueAsDate = new Date();

    await loadItems();

  } catch (error) {
    alert(error.message);
  } finally {
    submitButton.disabled = false;
  }
});


// Handle item actions: delete, mark returned, reopen
list.addEventListener("click", async (event) => {

  // Open image in lightbox
  const image = event.target.closest(".photo");

  if (image) {
    const box = document.createElement("div");

    box.className = "lightbox";

    const enlarged = document.createElement("img");

    enlarged.src = image.src;
    enlarged.alt = image.alt;

    box.appendChild(enlarged);

    box.addEventListener("click", () => box.remove());

    document.body.appendChild(box);

    return;
  }

  const button = event.target.closest("button[data-action]");

  if (!button) return;

  try {

    if (button.dataset.action === "delete") {

      await api(`/api/items/${button.dataset.id}`, {
        method: "DELETE"
      });

    } else {

      const item = items.find(
        entry => entry._id === button.dataset.id
      );

      if (!item) return;

      await api(`/api/items/${button.dataset.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          resolved: !item.resolved
        })
      });
    }

    await loadItems();

  } catch (error) {
    alert(error.message);
  }
});


// Filter buttons
chips.forEach(chip => {
  chip.addEventListener("click", () => {

    chips.forEach(c => c.classList.remove("active"));

    chip.classList.add("active");

    currentFilter = chip.dataset.filter;

    render();
  });
});


// Search items
search.addEventListener("input", render);


// Start by checking the login session
checkSession();
