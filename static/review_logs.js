async function loadPage(page = 1) {
    try {
        const res = await fetch(`/api/records?page=${page}`);
        const json = await res.json();

        const head = document.querySelector("#records-table-head");
        const body = document.querySelector("#table-body");
        const pagination = document.querySelector("#records-pagination");

        body.innerHTML = "";
        pagination.innerHTML = "";

        if (!json.data || json.data.length === 0) {
            head.innerHTML = "<tr><th>No data</th></tr>";
            body.innerHTML = "<tr><td>No scored records available.</td></tr>";
            return;
        }

        const columns = json.columns;

        head.innerHTML = `
            <tr>
                ${columns.map((col) => `<th>${col}</th>`).join("")}
            </tr>
        `;

        json.data.forEach((row) => {
            let tr = "<tr>";
            columns.forEach((col) => {
                const value = row[col] ?? "";
                tr += `<td>${value}</td>`;
            });
            tr += "</tr>";
            body.innerHTML += tr;
        });

        const totalPages = Math.ceil(json.total / json.per_page);
        renderPagination(json.page, totalPages);
        
    } catch (error) {
        const head = document.querySelector("#records-table-head");
        const body = document.querySelector("#table-body");

        head.innerHTML = "<tr><th>Error</th></tr>";
        body.innerHTML = `<tr><td>Failed to load records: ${error.message}</td></tr>`;
        console.error("loadPage error:", error);
    }
}

function renderPagination(currentPage, totalPages) {
    const pagination = document.querySelector("#records-pagination");
    pagination.innerHTML = "";

    const createBtn = (text, page, disabled = false, active = false) => {
        const btn = document.createElement("button");
        btn.textContent = text;
        btn.className = "page-btn";

        if (active) btn.classList.add("active");
        if (disabled) btn.disabled = true;

        btn.addEventListener("click", () => loadPage(page));
        return btn;
    };

    // Prev button
    pagination.appendChild(createBtn("«", currentPage - 1, currentPage === 1));

    const range = 2; // how many pages around current

    let start = Math.max(1, currentPage - range);
    let end = Math.min(totalPages, currentPage + range);

    if (start > 1) {
        pagination.appendChild(createBtn("1", 1));
        if (start > 2) {
            const dots = document.createElement("span");
            dots.textContent = "...";
            dots.className = "pagination-dots";
            pagination.appendChild(dots);
        }
    }

    for (let p = start; p <= end; p++) {
        pagination.appendChild(createBtn(p, p, false, p === currentPage));
    }

    if (end < totalPages) {
        if (end < totalPages - 1) {
            const dots = document.createElement("span");
            dots.textContent = "...";
            dots.className = "pagination-dots";
            pagination.appendChild(dots);
        }
        pagination.appendChild(createBtn(totalPages, totalPages));
    }

    // Next button
    pagination.appendChild(createBtn("»", currentPage + 1, currentPage === totalPages));
}

document.addEventListener("DOMContentLoaded", () => {
    loadPage(1);
});
