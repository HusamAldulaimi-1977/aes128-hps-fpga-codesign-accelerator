# aes128-hps-fpga-codesign-accelerator
AES-128 hardware/software co-design using HPS–FPGA architecture on Cyclone V (DE1-SoC), with ARM Cortex-A9 controlling an FPGA-based encryption accelerator.
Overview:
This project implements an AES-128 encryption hardware/software co-design using the Cyclone V SoC (DE1-SoC) platform. The design leverages the ARM Cortex-A9 Hard Processor System (HPS) for software control and an FPGA-based AES-128 accelerator for high-performance encryption.
The HPS communicates with the FPGA through memory-mapped AXI bridges, sending plaintext and key data to the hardware accelerator and receiving the resulting ciphertext.
This project demonstrates hardware/software partitioning, FPGA acceleration, and embedded Linux user-space control of custom RTL logic.

System Architecture
Hardware

Platform: DE1-SoC (Cyclone V)
FPGA Fabric: Custom AES-128 encryption core (RTL)
Interconnect: HPS–FPGA Lightweight AXI bridge
Interfaces: Memory-mapped PIO registers

Software

Processor: ARM Cortex-A9 (HPS)
OS: Embedded Linux
Language: C
Access Method: /dev/mem + mmap()

Data Flow

User enters plaintext and key on the HPS (Linux terminal)
HPS writes data to FPGA registers
FPGA AES core performs encryption
Ciphertext is returned to HPS and printed
HPS performs decryption to verify FPGA encryption.

Features

AES-128 encryption implemented in FPGA hardware
HPS–FPGA communication using AXI memory mapping
Linux user-space control (no kernel driver required)
Parameterized 128-bit key and plaintext input
Demonstrates HW acceleration vs SW execution model
Modular and extensible design

Tools & Technologies:

Intel Quartus Prime
Platform Designer (Qsys)
Altera SoC EDS
Embedded Linux
C / Verilog
Memory-mapped I/O (mmap)

Author

Husam Al-Dulaimi
M.S. Electrical Engineering
University of Texas at Dallas
