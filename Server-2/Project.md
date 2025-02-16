server2/
│── kernel/                 # Core analysis modules
│   │── __init__.py
│   │── network_analyzer.py
│   │── disk_analyzer.py
│   │── memory_analyzer.py
│   │── kernel_manager.py   # Central kernel controller
│── database/               # Database interactions
│   │── __init__.py
│   │── db_handler.py       # Handles storing & fetching data
│── grpc_service/           # gRPC services for Server-1 communication
│   │── __init__.py
│   │── server2.proto       # gRPC definitions
│   │── server2_pb2.py      # Auto-generated gRPC classes
│   │── server2_pb2_grpc.py
│   │── grpc_server.py      # gRPC server logic
│── config/                 # Config & settings
│   │── settings.py
│── utils/                  # Helper functions
│   │── __init__.py
│   │── logger.py
│── main.py                 # Entry point
│── requirements.txt         # Dependencies
│── README.md
