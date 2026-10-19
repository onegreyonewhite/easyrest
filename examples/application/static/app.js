async function login(email, password) {
  const response = await fetch("/restapi/v1/login/", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: email, password: password }),
  });
  return response.json();
}

async function loadTodos() {
  const response = await fetch("/restapi/v1/todos/", { credentials: "include" });
  return response.json();
}

function renderTodos(payload) {
  const list = document.querySelector("#todos");
  const rows = payload && payload.results ? payload.results : [];
  list.replaceChildren();
  for (const row of rows) {
    const item = document.createElement("li");
    item.textContent = row.title || "";
    list.appendChild(item);
  }
}

document.querySelector("#login").addEventListener("submit", async function (event) {
  event.preventDefault();
  const form = event.currentTarget;
  const body = await login(form.email.value, form.password.value);
  document.querySelector("#status").textContent = body.sub || body.error || "";
  renderTodos(await loadTodos());
});

loadTodos().then(renderTodos);
