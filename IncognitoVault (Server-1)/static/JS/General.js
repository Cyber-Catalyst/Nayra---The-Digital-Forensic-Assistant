$(document).ready(function() {
    $('#startBtn').click(function() {
        $.get('/start_sniffing', function(response) {
            $('#startBtn').prop('disabled', true);
            $('#stopBtn').prop('disabled', false);
        });
    });

    $('#stopBtn').click(function() {
        $.get('/stop_sniffing', function(response) {
            $('#startBtn').prop('disabled', false);
            $('#stopBtn').prop('disabled', true);
        });
    });

    function fetchPackets() {
        $.get('/get_packets', function(response) {
            if (response.packets.length > 0) {
                response.packets.forEach(function(packet) {
                    $('#packetTableBody').append(
                        `<tr>
                            <td>${packet.serial_no}</td>
                            <td>${packet.time}</td>
                            <td>${packet.src}</td>
                            <td>${packet.dst}</td>
                            <td>${packet.protocol}</td>
                            <td>${packet.length}</td>
                            <td>${packet.info}</td>
                        </tr>`
                    );
                });
            }
        });
    }

    setInterval(fetchPackets, 1000);
});

// JS Code for the Gauges in Dashboard
let uptimeGauge, cpuGauge, memoryGauge, swapGauge, diskGauge, uploadGauge, downloadGauge, pingGauge, latencyGauge;

function initializeGauges() {
    if (typeof JustGage !== 'undefined') {
        uptimeGauge = createGauge("uptime-meter", "System Uptime", "minutes", 0, 1440);
        cpuGauge = createGauge("cpu-meter", "CPU Usage");
        memoryGauge = createGauge("memory-meter", "Memory Usage");
        swapGauge = createGauge("swap-meter", "Swap Usage");
        diskGauge = createGauge("disk-meter", "Disk Usage");
        uploadGauge = createGauge("upload-meter", "Upload Speed", "Mbps");
        downloadGauge = createGauge("download-meter", "Download Speed", "Mbps");
        pingGauge = createGauge("ping-meter", "Ping Latency", "ms");
        latencyGauge = createGauge("latency-meter", "Data Collection Latency", "seconds");
    } else {
        console.error("JustGage is not defined. Please check the script loading.");
    }
}

function createGauge(id, title, unit = "%", min = 0, max = 100) {
    return new JustGage({
        id,
        value: 0,
        min,
        max,
        title,
        label: unit,
        levelColors: ["#FF5733", "#FFC300", "#28B463"],
        pointer: true,
        gaugeWidthScale: 0.5,
        relativeGaugeSize: true,
        labelFontColor: "#FFFFFF",
        valueFontColor: "#FFFFFF",
        valueFontSize: 25,
        valueFontWeight: "bold",
        donut: true,
        pointerOptions: { color: "#2C3E50", strokeWidth: 6 },
        animationSpeed: 300
    });
}

function smoothUpdateGauge(gauge, newValue) {
    if (!gauge) return;
    let currentValue = gauge.config.value;
    let step = (newValue - currentValue) / 20;
    let count = 0;
    function animate() {
        if (count < 20) {
            currentValue += step;
            gauge.refresh(Math.round(currentValue * 100) / 100);
            count++;
            requestAnimationFrame(animate);
        } else {
            gauge.refresh(newValue);
        }
    }
    animate();
}

function updateLEDIndicator(ledId, status) {
    const led = document.getElementById(ledId);
    if (led) {
        if (status.includes('Connected')) {
            led.classList.add('green');
            led.classList.remove('red');
        } else {
            led.classList.add('red');
            led.classList.remove('green');
        }
    }
}

async function fetchHealthData() {
    try {
        const response = await fetch('/health');
        const healthData = await response.json();

        function parseValue(data, key) {
            return data[key] && typeof data[key] === 'string' ? parseFloat(data[key].split(' ')[0]) || 0 : 0;
        }

        smoothUpdateGauge(uptimeGauge, parseValue(healthData, 'system_uptime'));
        smoothUpdateGauge(cpuGauge, parseValue(healthData, 'cpu_usage'));
        smoothUpdateGauge(memoryGauge, parseValue(healthData, 'memory_usage'));
        smoothUpdateGauge(swapGauge, parseValue(healthData, 'swap_usage'));
        smoothUpdateGauge(diskGauge, parseValue(healthData, 'disk_usage'));
        smoothUpdateGauge(uploadGauge, parseValue(healthData, 'upload_speed'));
        smoothUpdateGauge(downloadGauge, parseValue(healthData, 'download_speed'));
        smoothUpdateGauge(pingGauge, parseValue(healthData, 'ping_latency'));
        smoothUpdateGauge(latencyGauge, parseValue(healthData, 'data_latency'));

        if (healthData.redis_status) {
            updateLEDIndicator('redis-led', healthData.redis_status);
        }
        if (healthData.mysql_status) {
            updateLEDIndicator('mysql-led', healthData.mysql_status);
        }

    } catch (error) {
        console.error('Error fetching health data:', error);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    initializeGauges();
    fetchHealthData();
    setInterval(fetchHealthData, 100);
});
