document.addEventListener('DOMContentLoaded', function() {
    fetchThreats();
    loadUsername(); // Load username for auto-fill

    document.getElementById('search').addEventListener('input', filterThreats);
    document.getElementById('filter').addEventListener('change', filterThreats);

    // Scan button
    const scanBtn = document.getElementById('scan-btn');
    if (scanBtn) {
        scanBtn.addEventListener('click', runScan);
    }

    // Export and import buttons
    document.getElementById('export-record-btn').addEventListener('click', exportCompleteRecord);
    document.getElementById('import-record-btn').addEventListener('click', importCompleteRecord);


});

let allThreats = [];

function fetchThreats() {
    fetch('/api/threats')
        .then(response => response.json())
        .then(data => {
            allThreats = data;
            displayThreats(data);
            updateChart(data);
            // Store data locally
            localStorage.setItem('threatData', JSON.stringify(data));
        })
        .catch(error => console.error('Error fetching threats:', error));
}

function displayThreats(threats) {
    const container = document.getElementById('threats-container');
    container.innerHTML = '';
    threats.forEach(threat => {
        const threatDiv = document.createElement('div');
        threatDiv.className = 'col-md-4 mb-3';
        threatDiv.innerHTML = `
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">${threat.type}</h5>
                    <p class="card-text">${threat.value}</p>
                    <span class="badge bg-secondary">${threat.source}</span>
                </div>
            </div>
        `;
        container.appendChild(threatDiv);
    });
}

function filterThreats() {
    const searchTerm = document.getElementById('search').value.toLowerCase();
    const filterSource = document.getElementById('filter').value;
    const filtered = allThreats.filter(threat => {
        const matchesSearch = threat.type.toLowerCase().includes(searchTerm) ||
                              threat.value.toLowerCase().includes(searchTerm) ||
                              threat.source.toLowerCase().includes(searchTerm);
        const matchesFilter = !filterSource || threat.source === filterSource;
        return matchesSearch && matchesFilter;
    });
    displayThreats(filtered);
}

function updateChart(threats) {
    const ctx = document.getElementById('threatChart').getContext('2d');
    const sourceCounts = {};
    threats.forEach(threat => {
        sourceCounts[threat.source] = (sourceCounts[threat.source] || 0) + 1;
    });
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: Object.keys(sourceCounts),
            datasets: [{
                data: Object.values(sourceCounts),
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Threats by Source'
                }
            }
        }
    });
}

function runScan() {
    fetch('/api/threats')
        .then(response => response.json())
        .then(data => {
            const newThreats = data.filter(t => t.source === 'Local Scan' || t.source === 'File Upload' || t.source === 'URL Scan');
            const modal = new bootstrap.Modal(document.getElementById('scanModal'));
            const resultsDiv = document.getElementById('scan-results');
            if (newThreats.length > 0) {
                resultsDiv.innerHTML = '<h6>New threats detected:</h6><ul>' + newThreats.map(t => `<li>${t.type}: ${t.value} (Source: ${t.source})</li>`).join('') + '</ul>';
            } else {
                resultsDiv.innerHTML = '<p>No new threats detected.</p>';
            }
            modal.show();
        })
        .catch(error => console.error('Error running scan:', error));
}



// Function to export complete record as JSON
function exportCompleteRecord() {
    const threatData = localStorage.getItem('threatData');
    const username = localStorage.getItem('username');
    const completeRecord = {
        username: username,
        threats: threatData ? JSON.parse(threatData) : [],
        exportDate: new Date().toISOString()
    };
    const dataStr = JSON.stringify(completeRecord, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'complete_record.json';
    a.click();
    alert('Complete record exported. For security, consider hiding or encrypting this file.');
}

// Function to import complete record from JSON
function importCompleteRecord() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = function(event) {
        const file = event.target.files[0];
        const reader = new FileReader();
        reader.onload = function(e) {
            try {
                const data = JSON.parse(e.target.result);
                if (data.username) localStorage.setItem('username', data.username);
                if (data.threats) localStorage.setItem('threatData', JSON.stringify(data.threats));
                alert('Data imported successfully. Refresh the page to see changes.');
            } catch (error) {
                alert('Invalid file format.');
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

// Function to store username after login
function storeUsername(username) {
    localStorage.setItem('username', username);
}

// Function to load username for auto-fill
function loadUsername() {
    const username = localStorage.getItem('username');
    if (username) {
        const usernameInput = document.getElementById('username');
        if (usernameInput) usernameInput.value = username;
    }
}
