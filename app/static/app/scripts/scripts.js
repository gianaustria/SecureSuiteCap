
// static/js/scripts.js

// Get CSRF token for AJAX POST requests
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Tab navigation
function showSection(sectionId) {
    console.log(`Switching to section: ${sectionId}`); // Debug
    document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
    const section = document.getElementById(sectionId);
    if (section) section.classList.remove('hidden');
    else console.error(`Section not found: ${sectionId}`);
    document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
    const activeTab = document.querySelector(`.nav-link[onclick="showSection('${sectionId}')"]`);
    if (activeTab) activeTab.classList.add('active');
    else console.error(`No tab found for section: ${sectionId}`);

    if (sectionId === 'logs') fetchLogs();
    else if (sectionId === 'visualization') fetchVisualizations();
    else if (sectionId === 'collaboration') fetchCollaboration();
    else if (sectionId === 'policies') fetchPolicies();
}

// Fetch logs
async function fetchLogs() {
    try {
        const response = await fetch('/logs/');
        if (!response.ok) throw new Error(`Logs fetch failed: ${response.status}`);
        document.getElementById('logsList').innerHTML = await response.text();
    } catch (error) {
        console.error('Error fetching logs:', error);
        document.getElementById('logsList').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load logs: ${error.message}</div>`;
    }
}

// Fetch visualizations
async function fetchVisualizations() {
    try {
        const response = await fetch('/visualizations/');
        if (!response.ok) throw new Error(`Visualizations fetch failed: ${response.status}`);
        document.getElementById('visualizationList').innerHTML = await response.text();
    } catch (error) {
        console.error('Error fetching visualizations:', error);
        document.getElementById('visualizationList').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load visualizations: ${error.message}</div>`;
    }
}

// Fetch collaboration messages
async function fetchCollaboration() {
    try {
        const response = await fetch('/collaboration/');
        if (!response.ok) throw new Error(`Collaboration fetch failed: ${response.status}`);
        document.getElementById('collabList').innerHTML = await response.text();
    } catch (error) {
        console.error('Error fetching collaboration:', error);
        document.getElementById('collabList').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load collaboration: ${error.message}</div>`;
    }
}

// Fetch policies
async function fetchPolicies() {
    try {
        const response = await fetch('/policies/');
        if (!response.ok) throw new Error(`Policies fetch failed: ${response.status}`);
        document.getElementById('policiesForm').innerHTML = await response.text() + '<button type="submit" class="btn btn-primary bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded-lg transition-colors mt-4">Update Policies</button>';
    } catch (error) {
        console.error('Error fetching policies:', error);
        document.getElementById('policiesForm').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load policies: ${error.message}</div>`;
    }
}

// Show graph for visualizations
async function showGraph(index) {
    try {
        const response = await fetch(`/visualization/${index}/`);
        if (!response.ok) throw new Error(`Visualization fetch failed: ${response.status}`);
        const data = await response.json();
        if (data.error) {
            alert(data.error);
            return;
        }
        const ctx = document.getElementById('visualizationChart').getContext('2d');
        if (window.chart) window.chart.destroy();
        window.chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['File Size'],
                datasets: [{
                    label: 'Size (bytes)',
                    data: [data.stats.size],
                    backgroundColor: '#3b82f6',
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    } catch (error) {
        console.error('Error showing graph:', error);
        alert('Failed to load graph: ' + error.message);
    }
}

// File upload form submission
document.getElementById('uploadForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    console.log('Upload form submitted'); // Debug
    const formData = new FormData(e.target);
    try {
        const response = await fetch('/upload/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: formData
        });
        if (!response.ok) throw new Error(`Upload failed: ${response.status}`);
        const results = await response.json();
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = results.map(r => `
            <div class="bg-green-50 border border-green-200 rounded-lg p-4 shadow-sm">
                <strong class="text-green-800">File:</strong> ${r.filename}<br>
                ${r.error ? `<strong class="text-red-600">Error:</strong> ${r.error}` : `
                    <strong class="text-green-800">Size:</strong> ${r.stats.size} bytes<br>
                    <strong class="text-green-800">Type:</strong> ${r.stats.type}<br>
                    <strong class="text-green-800">Malware Status:</strong> <span class="${r.stats.malware_status.includes('Malicious') ? 'text-red-600' : 'text-green-600'}">${r.stats.malware_status}</span><br>
                    <strong class="text-green-800">Malware Details:</strong> ${Object.keys(r.stats.malware_details).length > 0
                    ? '<ul class="list-disc pl-5">' + Object.entries(r.stats.malware_details).map(([vendor, result]) =>
                        `<li>${vendor}: ${result.result || 'Detected'}</li>`
                    ).join('') + '</ul>'
                    : 'None'
                }<br><br><br>
                    ${r.excel_path ? `<a href="${r.excel_path}" class="btn btn-sm btn-primary bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded inline-block mt-2">Download Excel</a>` : ''}
                `}
            </div>
        `).join('');
    } catch (error) {
        console.error('Error uploading file:', error);
        document.getElementById('results').innerHTML = `<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to upload: ${error.message}</div>`;
    }
});

// Collaboration form submission
document.getElementById('collabForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    console.log('Collaboration form submitted'); // Debug
    const formData = new FormData(e.target);
    try {
        const response = await fetch('/collaboration/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: formData
        });
        if (!response.ok) throw new Error(`Collaboration submission failed: ${response.status}`);
        fetchCollaboration();
        e.target.reset();
    } catch (error) {
        console.error('Error submitting collaboration:', error);
        alert('Failed to submit message: ' + error.message);
    }
});

// Policies form submission
document.getElementById('policiesForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    console.log('Policies form submitted'); // Debug
    const formData = new FormData(e.target);
    try {
        const response = await fetch('/policies/', {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: formData
        });
        if (!response.ok) throw new Error(`Policies submission failed: ${response.status}`);
        fetchPolicies();
    } catch (error) {
        console.error('Error submitting policies:', error);
        alert('Failed to update policies: ' + error.message);
    }
});

// Initialize tabs on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing tabs');
    // Only initialize tabs if the page has sections (e.g., not website_checker.html)
    if (document.getElementById('upload')) {
        showSection('upload'); // Set default tab only if 'upload' section exists
    }
});

// Add this to the <script> block in website_checker.html or scripts.js

// Get CSRF token for AJAX POST requests
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Check Availability function
async function checkAvailability() {
    const urlInput = document.getElementById('url').value;
    const resultElement = document.getElementById('checkResult');

    if (!urlInput) {
        resultElement.textContent = 'Error: Please enter a URL';
        return;
    }

    try {
        const response = await fetch('/check/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        resultElement.textContent = data.result;
        resultElement.className = data.result.includes('Error') ? 'text-danger mt-2 d-block' : 'text-success mt-2 d-block';
    } catch (error) {
        resultElement.textContent = `Error: ${error.message}`;
        resultElement.className = 'text-danger mt-2 d-block';
    }
}

// Homepage Test function
async function runHomepageTest() {
    const urlInput = document.getElementById('url').value;
    const outputElement = document.getElementById('homepageOutput');

    if (!urlInput) {
        outputElement.value = 'Error: Please enter a URL';
        return;
    }

    try {
        const response = await fetch('/homepage/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        outputElement.value = data.result;
    } catch (error) {
        outputElement.value = `Error: ${error.message}`;
    }
}

// Ping Test function
async function runPingTest() {
    const urlInput = document.getElementById('url').value;
    const outputElement = document.getElementById('pingOutput');

    if (!urlInput) {
        outputElement.value = 'Error: Please enter a URL';
        return;
    }

    try {
        const response = await fetch('/ping/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        outputElement.value = data.result;
    } catch (error) {
        outputElement.value = `Error: ${error.message}`;
    }
}

// Traceroute Test function
async function runTracerouteTest() {
    const urlInput = document.getElementById('url').value;
    const outputElement = document.getElementById('tracerouteOutput');

    if (!urlInput) {
        outputElement.value = 'Error: Please enter a URL';
        return;
    }

    try {
        const response = await fetch('/traceroute/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        outputElement.value = data.result;
    } catch (error) {
        outputElement.value = `Error: ${error.message}`;
    }
}

// DNS Security Check function
async function runDnsCheck() {
    const urlInput = document.getElementById('url').value;
    const outputElement = document.getElementById('dnsOutput');

    if (!urlInput) {
        outputElement.value = 'Error: Please enter a URL';
        return;
    }

    try {
        const response = await fetch('/dns/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        outputElement.value = data.result;
    } catch (error) {
        outputElement.value = `Error: ${error.message}`;
    }
}