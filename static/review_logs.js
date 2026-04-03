async function loadTablePage({ page = 1, apiUrl, headSelector, bodySelector, paginationSelector, emptyMessage, errorPrefix, reloadFn }) {
    try {
        const res = await fetch(`${apiUrl}?page=${page}`);
        const json = await res.json();

        const head = document.querySelector(headSelector);
        const body = document.querySelector(bodySelector);

        body.innerHTML = "";

        if (!json.data || json.data.length === 0) {
            head.innerHTML = "<tr><th>No data</th></tr>";
            body.innerHTML = `<tr><td>${emptyMessage}</td></tr>`;
            renderPagination(paginationSelector, 1, 1, reloadFn);
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
        renderPagination(paginationSelector, json.page, totalPages, reloadFn);
    } catch (error) {
        const head = document.querySelector(headSelector);
        const body = document.querySelector(bodySelector);

        head.innerHTML = "<tr><th>Error</th></tr>";
        body.innerHTML = `<tr><td>${errorPrefix}: ${error.message}</td></tr>`;
        console.error(`${errorPrefix}:`, error);
    }
}

function loadPage(page = 1) {
    return loadTablePage({
        page,
        apiUrl: "/api/records",
        headSelector: "#records-table-head",
        bodySelector: "#table-body",
        paginationSelector: "#records-pagination",
        emptyMessage: "No scored records available.",
        errorPrefix: "Failed to load records",
        reloadFn: loadPage,
    });
}

function loadFlowPage(page = 1) {
    return loadTablePage({
        page,
        apiUrl: "/api/flows",
        headSelector: "#flows-table-head",
        bodySelector: "#flows-table-body",
        paginationSelector: "#flows-pagination",
        emptyMessage: "No flow records available.",
        errorPrefix: "Failed to load flow records",
        reloadFn: loadFlowPage,
    });
}

function renderPagination(containerSelector, currentPage, totalPages, onPageClick) {
    const pagination = document.querySelector(containerSelector);
    pagination.innerHTML = "";

    const createBtn = (text, page, disabled = false, active = false) => {
        const btn = document.createElement("button");
        btn.textContent = text;
        btn.className = "page-btn";

        if (active) btn.classList.add("active");
        if (disabled) btn.disabled = true;

        btn.addEventListener("click", () => onPageClick(page));
        return btn;
    };

    pagination.appendChild(createBtn("«", currentPage - 1, currentPage === 1));

    const range = 2;
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

    pagination.appendChild(createBtn("»", currentPage + 1, currentPage === totalPages));
}

document.addEventListener("DOMContentLoaded", () => {
    loadPage(1);
    loadFlowPage(1);
});
