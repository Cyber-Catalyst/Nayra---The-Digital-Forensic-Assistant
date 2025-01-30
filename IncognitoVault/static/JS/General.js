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

    setInterval(fetchPackets, 1000);  // Fetch packets every second
});