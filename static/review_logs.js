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

function loadProtocolPage(page = 1) {
    fetch(`/api/protocol-evidence?page=${page}`)
        .then((res) => res.json())
        .then((json) => {
            const grid = document.getElementById("protocol-grid");
            grid.innerHTML = "";

            if (!json.data || json.data.length === 0) {
                grid.innerHTML = "<div class='muted'>No protocol evidence available.</div>";
                renderPagination("#protocol-pagination", 1, 1, loadProtocolPage);
                return;
            }

            json.data.forEach((row) => {
                const card = document.createElement("div");
                card.className = "protocol-card";

                card.innerHTML = `
                    <div class="protocol-card-header">
                        <strong>${(row.flow_protocol_hint || "UNKNOWN").toUpperCase()}</strong>
                        <span class="protocol-risk">${row.flow_risk_level || "N/A"}</span>
                    </div>

                    <div class="protocol-meta">
                        <div><strong>Flow:</strong> ${row.flow_src_ip}:${row.flow_src_port} -> ${row.flow_dst_ip}:${row.flow_dst_port}</div>
                        <div><strong>Risk Score:</strong> ${row.flow_risk_score}</div>
                    </div>
                `;

                // HTTP
                if (row.flow_http_method || row.flow_http_host || row.flow_http_path) {
                    card.innerHTML += `
                        <div class="protocol-block">
                            <div><strong>HTTP Method:</strong> ${row.flow_http_method || "N/A"}</div>
                            <div><strong>HTTP Host:</strong> ${row.flow_http_host || "N/A"}</div>
                            <div><strong>HTTP Path:</strong> ${row.flow_http_path || "N/A"}</div>
                        </div>
                    `;
                }

                // TLS
                if (row.flow_tls_sni) {
                    card.innerHTML += `
                        <div class="protocol-block">
                            <div><strong>TLS SNI:</strong> ${row.flow_tls_sni}</div>
                        </div>
                    `;
                }

                // SSH
                if (row.flow_protocol_hint === "ssh" || row.flow_ssh_seen) {
                    card.innerHTML += `
                        <div class="protocol-block">
                            <div><strong>Protocol:</strong> SSH</div>
                            <div><strong>SSH Banner:</strong> ${row.flow_ssh_banner || "N/A"}</div>
                            <div><strong>Detection Source:</strong> ${row.flow_ssh_detect_source || "N/A"}</div>
                        </div>
                    `;
                }

                grid.appendChild(card);
            });

            const totalPages = Math.ceil(json.total / json.per_page);
            renderPagination("#protocol-pagination", json.page, totalPages, loadProtocolPage);
        });
}

function renderPagination(containerSelector, currentPage, totalPages, onPageClick) {
    const pagination = document.querySelector(containerSelector);

    if (!pagination) {
        return;
    }

    pagination.innerHTML = "";

    if (totalPages <= 1) {
        return;
    }

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
    loadProtocolPage(1);
});
