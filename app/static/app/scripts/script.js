console.log('Script loaded');


(function () {
    let chartInstance = null;

    $(document).ready(function () {
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

        function showSection(sectionId) {
            $('.nav-link').removeClass('active bg-blue-100 text-blue-600').addClass('bg-white text-gray-700');
            $(`.nav-link[data-section="${sectionId}"]`).addClass('active bg-blue-100 text-blue-600');
            $('.section').addClass('hidden').removeClass('block');
            $(`#${sectionId}`).removeClass('hidden').addClass('block');

            if (sectionId === 'logs') loadLogs();
            else if (sectionId === 'collaboration') loadCollaboration();
            else if (sectionId === 'policies') loadPolicies();
            else if (sectionId === 'visualization') loadVisualization();
        }

        $('.nav-link').click(function (e) {
            e.preventDefault();
            const sectionId = $(this).data('section');
            if (sectionId) showSection(sectionId);
        });

        // Upload form AJAX handler
        $('#uploadForm').on('submit', function (e) {
            e.preventDefault();

            const formData = new FormData(this);
            const resultsDiv = $('#results');
            resultsDiv.html('Uploading...');

            $.ajax({
                url: '/upload/',  // Update if your upload URL differs
                type: 'POST',
                data: formData,
                processData: false,
                contentType: false,
                headers: { 'X-CSRFToken': getCookie('csrftoken') },
                success: function (data) {
                    if (data.success) {
                        if (data.results && data.results.length > 0) {
                            resultsDiv.html(data.results.map(r => `
                                <div class="bg-green-50 border border-green-200 rounded-lg p-4 shadow-sm mb-4">
                                    <strong>File:</strong> ${r.filename}<br>
                                    ${r.error ? `<strong class="text-red-600">Error:</strong> ${r.error}` : `
                                        <strong>Size:</strong> ${r.stats.size || 'Unknown'} bytes<br>
                                        <strong>Type:</strong> ${r.stats.type || 'Unknown'}<br>
                                        <strong>Malware Status:</strong> <span class="${r.stats.malware_status && r.stats.malware_status.includes('Malicious') ? 'text-red-600' : 'text-green-600'}">${r.stats.malware_status || 'Unknown'}</span><br>
                                        <strong>Malware Details:</strong> ${r.stats.malware_details && Object.keys(r.stats.malware_details).length > 0
                                        ? '<ul class="list-disc pl-5">' + Object.entries(r.stats.malware_details).map(([vendor, result]) =>
                                            `<li>${vendor}: ${result.result || 'Detected'}</li>`
                                        ).join('') + '</ul>'
                                        : 'None'
                                    }<br>
                                        ${r.excel_path ? `<a href="${r.excel_path}" class="inline-block bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded text-sm mt-2" target="_blank">Download Excel</a>` : ''}
                                    `}
                                </div>
                            `).join(''));
                        } else {
                            resultsDiv.html('<p>No upload results returned.</p>');
                        }
                    } else {
                        resultsDiv.html(`<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Upload error: ${data.error || 'Unknown error'}</div>`);
                    }
                },
                error: function (xhr, status, error) {
                    resultsDiv.html(`<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Upload failed: ${error}</div>`);
                }
            });
        });

        function loadVisualization() {
            const canvas = document.getElementById('visualizationChart');
            if (!canvas) return;

            const dataDiv = document.getElementById('visualizationData');
            const malicious = parseInt(dataDiv?.dataset?.malicious || '0');
            const nonMalicious = parseInt(dataDiv?.dataset?.nonMalicious || '0');

            const ctx = canvas.getContext('2d');
            if (chartInstance) chartInstance.destroy();

            chartInstance = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Malicious', 'Non-Malicious'],
                    datasets: [{
                        data: [malicious, nonMalicious],
                        backgroundColor: ['#ef4444', '#22c55e'],
                        borderColor: ['#b91c1c', '#15803d'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: { color: '#374151' }
                        }
                    }
                }
            });
        }

        async function loadLogs() {
            const logsList = $('#logsList');
            if (!logsList.length) return;

            try {
                const response = await fetch('/get_logs/', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });

                const contentType = response.headers.get("content-type") || "";
                if (!response.ok || !contentType.includes("application/json")) {
                    throw new Error("You must be logged in to view logs.");
                }

                const data = await response.json();
                logsList.html(data.logs.length ? data.logs.map(log => {
                    let stats = {};
                    try {
                        stats = typeof log.stats === 'string' ? JSON.parse(log.stats) : log.stats;
                    } catch {
                        stats = { size: 'Unknown', type: 'Unknown', malware_status: 'Unknown' };
                    }
                    return `
                <div class="border border-gray-200 p-4 rounded-lg">
                    <p><strong>File:</strong> ${log.filename}</p>
                    <p><strong>Status:</strong> ${log.status}</p>
                    <p><strong>User:</strong> ${log.user__username || 'Anonymous'}</p>
                    <p><strong>Created:</strong> ${new Date(log.created_at).toLocaleString()}</p>
                    <p><strong>Stats:</strong> Size: ${stats.size || 'Unknown'} bytes, Type: ${stats.type || 'Unknown'}, Malware: ${stats.malware_status || 'Unknown'}</p>
                </div>
            `;
                }).join('') : '<p class="text-gray-600">No logs available.</p>');
            } catch (error) {
                logsList.html(`<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load logs: ${error.message}</div>`);
            }
        }

        async function loadCollaboration() {
            const collabList = $('#collabList');
            if (!collabList.length) return;
            try {
                const response = await fetch('/get_collaboration/', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });
                const data = await response.json();
                collabList.html(data.messages.length ? data.messages.map(msg => `
                    <div class="border border-gray-200 p-4 rounded-lg">
                        <p><strong>Message:</strong> ${msg.message}</p>
                        <p><strong>Timestamp:</strong> ${new Date(msg.timestamp).toLocaleString()}</p>
                        <button onclick="editMessage(${msg.id})" class="bg-blue-600 text-white py-1 px-3 rounded text-sm">Edit</button>
                        <form action="/delete-message/${msg.id}/" method="POST" class="inline">
                            <input type="hidden" name="csrfmiddlewaretoken" value="${getCookie('csrftoken')}">
                            <button type="submit" class="bg-red-600 text-white py-1 px-3 rounded text-sm">Delete</button>
                        </form>
                    </div>
                `).join('') : '<p class="text-gray-600">No messages available.</p>');
            } catch (error) {
                collabList.html(`<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load messages: ${error.message}</div>`);
            }
        }

        window.editMessage = async function (messageId) {
            const messageText = prompt('Edit message:');
            if (messageText) {
                try {
                    const response = await fetch(`/edit-message/${messageId}/`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCookie('csrftoken'),
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: JSON.stringify({ message: messageText })
                    });
                    const data = await response.json();
                    if (data.success) loadCollaboration();
                    else alert('Error editing message: ' + (data.error || 'Unknown error'));
                } catch (error) {
                    alert('Failed to edit message: ' + error.message);
                }
            }
        };

        async function loadPolicies() {
            const policiesForm = $('#policiesForm');
            if (!policiesForm.length) return;
            try {
                const response = await fetch('/get_policies/', {
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });
                const data = await response.json();
                policiesForm.html(`
                    <div>
                        <label>Categories:</label>
                        ${data.policies.categories.map(cat => `
                            <div><input type="checkbox" name="categories" value="${cat}" checked> ${cat}</div>
                        `).join('')}
                    </div>
                    <div>
                        <label>Extensions:</label>
                        <input type="text" name="extensions" value="${data.policies.extensions}" class="w-full border rounded p-2">
                    </div>
                    <div>
                        <label>Keywords:</label>
                        <textarea name="keywords" class="w-full border rounded p-2">${data.policies.keywords}</textarea>
                    </div>
                    <button type="submit" class="bg-blue-600 text-white py-2 px-4 rounded">Update Policies</button>
                `);
            } catch (error) {
                policiesForm.html(`<div class="bg-red-100 border border-red-400 text-red-700 p-4 rounded">Failed to load policies: ${error.message}</div>`);
            }
        }

        if ($('#upload').length) showSection('upload');


        async function checkAvailability() {
            console.log('checkAvailability triggered');
            const urlInput = document.getElementById('url').value.trim();
            console.log('URL input:', urlInput);
            const resultElement = document.getElementById('checkResult');
            if (!urlInput) {
                resultElement.textContent = 'Error: Please enter a URL';
                resultElement.className = 'text-danger mt-2 d-block';
                return;
            }

            try {
                const response = await fetch('/check-availability/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken'),
                    },
                    body: JSON.stringify({ url: urlInput }),
                });
                console.log('Fetch response status:', response.status);
                const data = await response.json();
                console.log('Fetch response data:', data);
                resultElement.textContent = data.result;
                resultElement.className = data.result.includes('Error') ? 'text-danger mt-2 d-block' : 'text-success mt-2 d-block';
            } catch (error) {
                console.error('Fetch error:', error);
                resultElement.textContent = `Error: ${error.message}`;
                resultElement.className = 'text-danger mt-2 d-block';
            }
        }


        async function runHomepageTest() {
            const urlInput = document.getElementById('url').value.trim();
            const outputElement = document.getElementById('homepageOutput');
            if (!urlInput) {
                outputElement.value = 'Error: Please enter a URL';
                return;
            }

            try {
                const response = await fetch('/homepage-test/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken'),
                    },
                    body: JSON.stringify({ url: urlInput }),
                });
                const data = await response.json();
                outputElement.value = data.result;
            } catch (error) {
                outputElement.value = `Error: ${error.message}`;
            }
        }

        async function runPingTest() {
            const urlInput = document.getElementById('url').value.trim();
            const outputElement = document.getElementById('pingOutput');
            if (!urlInput) {
                outputElement.value = 'Error: Please enter a URL';
                return;
            }

            try {
                const response = await fetch('/ping-test/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken'),
                    },
                    body: JSON.stringify({ url: urlInput }),
                });
                const data = await response.json();
                outputElement.value = data.result;
            } catch (error) {
                outputElement.value = `Error: ${error.message}`;
            }
        }

        async function runTracerouteTest() {
            const urlInput = document.getElementById('url').value.trim();
            const outputElement = document.getElementById('tracerouteOutput');
            if (!urlInput) {
                outputElement.value = 'Error: Please enter a URL';
                return;
            }

            try {
                const response = await fetch('/traceroute-test/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken'),
                    },
                    body: JSON.stringify({ url: urlInput }),
                });
                const data = await response.json();
                outputElement.value = data.result;
            } catch (error) {
                outputElement.value = `Error: ${error.message}`;
            }
        }

        async function runDnsCheck() {
            const urlInput = document.getElementById('url').value.trim();
            const outputElement = document.getElementById('dnsOutput');
            if (!urlInput) {
                outputElement.value = 'Error: Please enter a URL';
                return;
            }

            try {
                const response = await fetch('/dns-check/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCookie('csrftoken'),
                    },
                    body: JSON.stringify({ url: urlInput }),
                });
                const data = await response.json();
                outputElement.value = data.result;
            } catch (error) {
                outputElement.value = `Error: ${error.message}`;
            }
        }

        $('#checkAvailabilityBtn').on('click', checkAvailability);
        $('#homepageTestBtn').on('click', runHomepageTest);
        $('#pingTestBtn').on('click', runPingTest);
        $('#tracerouteTestBtn').on('click', runTracerouteTest);
        $('#dnsTestBtn').on('click', runDnsCheck);
    });
})();
