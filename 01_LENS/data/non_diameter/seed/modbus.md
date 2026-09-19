## 1) Read-Holding-Registers - Quantity-of-Registers
**Message:** Read-Holding-Registers (RHR)
**Target Register's path:** Quantity-of-Registers
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses incoming requests and allocates response buffers based on the field values in the received PDU, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack implementation does not properly validate the Quantity of Registers field against the protocol-specified maximum before using it for internal buffer allocation or memory operations; (iii) according to the Modbus specification Section 6.3, the valid range for Quantity of Registers in a Read-Holding-Registers request is 1 to 125 (0x0001 to 0x007D), but the protocol field encoding allows any 16-bit value (0x0000 to 0xFFFF); (iv) the PLC's firmware uses the received Quantity value directly to calculate response buffer size (Quantity × 2 bytes) or loop iteration count without bounds checking; and (v) the attacker has obtained the target PLC's IP address and Unit Identifier.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message Read-Holding-Registers (function code 0x03), constructing a valid MBAP header with a unique Transaction Identifier, Protocol Identifier 0x0000, correct Length field (6 bytes), and the target Unit Identifier. The PDU contains function code 0x03, Starting Address 0x0000, and a malicious Quantity of Registers value 0xFFFF (65535), which far exceeds the protocol-specified maximum of 125. The attacker sends this Modbus TCP frame to the victim PLC on TCP port 502.

When the PLC's protocol stack receives this request, it attempts to process the Quantity value 65535. If the implementation uses this value to allocate a response buffer (65535 × 2 = 131070 bytes), it may exhaust available heap memory on resource-constrained PLC hardware (which typically has 64-256KB RAM), causing a memory allocation failure and firmware crash. Alternatively, if the implementation uses a fixed-size stack buffer and copies Quantity × 2 bytes into it, this causes a stack buffer overflow, potentially corrupting the return address and crashing the PLC's main control loop. In either case, the PLC stops executing its control program, all physical outputs freeze in their last state or go to a fail-safe condition, and the SCADA master loses communication with the device. The PoC is successful if the PLC crashes, becomes unresponsive on TCP port 502, or enters a fault state after receiving the single malformed request.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mbap_header": {
    "transaction_id": "0x0001",
    "protocol_id": "0x0000",
    "length": 6,
    "unit_id": 1
  },
  "pdu": {
    "function_code": "0x03",
    "starting_address": "0x0000",
    "quantity_of_registers": "0xFFFF"
  }
}

**Classification:**
ATTACK


## 2) Write-Multiple-Coils - Quantity-of-Outputs
**Message:** Write-Multiple-Coils (WMC)
**Target Register's path:** Quantity-of-Outputs
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses Write-Multiple-Coils requests and processes the Quantity of Outputs field to determine how many coil states to update in its internal data model, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack implementation does not properly validate the consistency between the Quantity of Outputs field, the Byte Count field, and the actual payload length in the received PDU; (iii) according to the Modbus specification Section 6.11, the valid range for Quantity of Outputs is 1 to 1968 (0x0001 to 0x07B0), and Byte Count must equal ceil(Quantity / 8); (iv) the PLC's firmware trusts the Quantity of Outputs value to determine the number of coils to iterate over during the write operation, without verifying it matches the actually received data bytes; and (v) the attacker has obtained the target PLC's IP address and Unit Identifier.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message Write-Multiple-Coils (function code 0x0F), constructing a valid MBAP header with the target Unit Identifier. The PDU contains function code 0x0F, Starting Address 0x0000, a malicious Quantity of Outputs 0xFFFF (65535, far exceeding the protocol maximum of 1968), Byte Count 0x01 (claiming only 1 byte of coil data follows), and a single Outputs Value byte 0x00. The critical exploit is the mismatch: Quantity claims 65535 coils, but only 1 byte (8 coils worth) of actual data is provided.

When the PLC's protocol stack processes this request, if the implementation uses the Quantity field (65535) to control its write loop but reads coil values from the received data buffer that only contains 1 byte, the loop reads far beyond the end of the received packet buffer (a heap buffer over-read). This can leak sensitive memory contents, corrupt adjacent heap metadata, or trigger a segmentation fault crashing the PLC firmware. On resource-constrained PLC hardware, the firmware may also attempt to write to 65535 coil addresses in its internal data table, overflowing the coil address space and corrupting adjacent memory regions (registers, discrete inputs, or firmware data structures). The PoC is successful if the PLC crashes, enters a fault state, or becomes unresponsive on TCP port 502 after receiving this single malformed request.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mbap_header": {
    "transaction_id": "0x0002",
    "protocol_id": "0x0000",
    "length": 8,
    "unit_id": 1
  },
  "pdu": {
    "function_code": "0x0F",
    "starting_address": "0x0000",
    "quantity_of_outputs": "0xFFFF",
    "byte_count": 1,
    "outputs_value": "0x00"
  }
}

**Classification:**
ATTACK


## 3) Read-Discrete-Inputs - Quantity-of-Inputs
**Message:** Read-Discrete-Inputs (RDI)
**Target Register's path:** Quantity-of-Inputs
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses Read-Discrete-Inputs requests and uses the Quantity of Inputs field for response construction and internal iteration, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack implementation does not properly validate the Quantity of Inputs field against the protocol-specified minimum before using it in arithmetic operations; (iii) according to the Modbus specification Section 6.2, the valid range for Quantity of Inputs is 1 to 2000 (0x0001 to 0x07D0), and the response Byte Count is calculated as ceil(Quantity / 8); (iv) the PLC's firmware uses the Quantity value directly in division operations (Quantity / 8) or as a loop bound without checking for zero; and (v) the attacker has obtained the target PLC's IP address and Unit Identifier.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message Read-Discrete-Inputs (function code 0x02), constructing a valid MBAP header with the target Unit Identifier. The PDU contains function code 0x02, Starting Address 0x0000, and a malicious Quantity of Inputs 0x0000 (zero, below the protocol-specified minimum of 1). The attacker sends this Modbus TCP frame to the victim PLC on TCP port 502.

When the PLC's protocol stack processes this request, the zero Quantity value triggers several potential implementation failures. First, if the firmware calculates response Byte Count as ceil(0 / 8), depending on the integer arithmetic implementation (especially in C on embedded systems), this may produce an unexpected result or be used to allocate a zero-length buffer, which on many embedded memory allocators returns NULL or a minimal block that is subsequently overwritten. Second, if the implementation uses Quantity as a loop bound in a do-while loop (which executes at least once regardless of the bound), it may perform one unintended iteration with underflow when decrementing a zero unsigned counter, wrapping to 0xFFFF and causing a massive loop execution. Third, some implementations may attempt to construct a response with 0 data bytes, producing a malformed response frame that corrupts the TCP stream state machine. The PoC is successful if the PLC crashes, hangs in an infinite loop, becomes unresponsive, or produces anomalous behavior after receiving this single request with zero Quantity.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mbap_header": {
    "transaction_id": "0x0003",
    "protocol_id": "0x0000",
    "length": 6,
    "unit_id": 1
  },
  "pdu": {
    "function_code": "0x02",
    "starting_address": "0x0000",
    "quantity_of_inputs": "0x0000"
  }
}

**Classification:**
ATTACK


## 4) Read-Input-Registers - Starting-Address
**Message:** Read-Input-Registers (RIR)
**Target Register's path:** Starting-Address
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses Read-Input-Registers requests and computes the register address range to read from using Starting Address and Quantity fields, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack implementation validates Starting Address and Quantity independently but does not check for 16-bit unsigned integer overflow when computing the end address (Starting Address + Quantity); (iii) according to the Modbus specification Section 6.4, Starting Address is 0x0000 to 0xFFFF and Quantity is 1 to 125, and the implementation should verify that all requested registers exist before responding; (iv) the PLC's firmware computes the end address as a 16-bit unsigned addition, causing a wraparound when the sum exceeds 0xFFFF, and uses the wrapped result for address range checking; and (v) the attacker has obtained the target PLC's IP address and Unit Identifier.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.

**Attack Procedure:**
The attacker crafts an Attack Message Read-Input-Registers (function code 0x04), constructing a valid MBAP header with the target Unit Identifier. The PDU contains function code 0x04, Starting Address 0xFFFF (the maximum 16-bit address), and Quantity of Registers 0x007D (125, which is valid on its own per the specification). The attacker sends this Modbus TCP frame to the victim PLC on TCP port 502.

When the PLC's protocol stack processes this request, it computes the end address as Starting Address + Quantity = 0xFFFF + 125 = 0x1007C. On a 16-bit unsigned integer, this wraps around to 0x007C (124). The implementation may then check that the "end address" 0x007C is within the valid register range (which it is, since low-address registers typically exist), passing the bounds check. However, the actual memory read starts at the offset corresponding to address 0xFFFF in the register data table. If the PLC's register table only has entries for addresses 0-999 (a common configuration), the read begins far beyond the allocated table boundary, causing an out-of-bounds memory read. This leaks firmware memory contents (information disclosure of encryption keys, passwords, or firmware code), or triggers a segmentation fault / hardware memory protection exception that crashes the PLC. The PoC is successful if the PLC responds with leaked memory contents from beyond its register table, crashes, or becomes unresponsive after receiving this single request.

**Attack Message:**
The following is the attack packet represented in a fixed JSON structure. This packet can be used to verify the PoC in a real environment.

{
  "mbap_header": {
    "transaction_id": "0x0004",
    "protocol_id": "0x0000",
    "length": 6,
    "unit_id": 1
  },
  "pdu": {
    "function_code": "0x04",
    "starting_address": "0xFFFF",
    "quantity_of_registers": "0x007D"
  }
}

**Classification:**
ATTACK


## 5) Write-Single-Register - Register-Value
**Message:** Write-Single-Register (WSR)
**Target Register's path:** Register-Value
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses Write-Single-Register requests and stores the Register Value into its holding register data table, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack parses the Register Value field from Write-Single-Register requests per specification Section 6.6; and (iii) the attacker has obtained the target PLC's IP address, Unit Identifier, and a valid holding register address.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.
**Security Analysis:**
Write-Single-Register (function code 0x06) has a fixed-length PDU structure defined in Modbus specification Section 6.6: function code (1 byte) + Register Address (2 bytes) + Register Value (2 bytes) = exactly 5 bytes. The Register Value field is always exactly 2 bytes (16 bits), and the Modbus specification defines the entire range 0x0000 to 0xFFFF as valid register content values with no restricted or reserved values. Unlike variable-length fields such as Quantity of Registers (which have protocol-specified minimum and maximum bounds), the Register Value field has no boundary constraints to violate. The PLC implementation simply copies the 2-byte value into the addressed holding register slot using a fixed-size memory write operation. There is no dynamic buffer allocation based on this field, no arithmetic computation using it as a size or count, and no loop iteration controlled by it. Regardless of what 16-bit value the attacker places in the Register Value field (0x0000, 0xFFFF, or any value in between), the parsing and storage operation is identical: read 2 bytes from a fixed PDU offset and write them to a fixed-size register slot. This field cannot trigger buffer overflows, integer overflows, division-by-zero, or any implementation-level memory corruption through boundary violation. While writing a specific value may affect the physical process controlled by the register (a concern under a different threat model), it cannot cause the protocol stack implementation to crash or exhibit undefined behavior.

**Classification:**
SAFE


## 6) Write-Single-Coil - Output-Value
**Message:** Write-Single-Coil (WSC)
**Target Register's path:** Output-Value
**Threat Model:**
- **Attack Assumption:**
In the target industrial control network, a Modbus TCP slave device (PLC/RTU) runs a Modbus TCP protocol stack implementation that parses Write-Single-Coil requests and updates a single coil state based on the Output Value field, using the Modbus Application Protocol (Modbus Specification V1.1b3).
We assume: (i) the victim PLC's Modbus TCP port (TCP 502) is reachable from the attacker's network segment; (ii) the PLC's Modbus TCP protocol stack parses the Output Value field from Write-Single-Coil requests per specification Section 6.5; and (iii) the attacker has obtained the target PLC's IP address, Unit Identifier, and a valid coil address.
- **Attacker Capability:**
The attacker is restricted to only send one Modbus TCP request message and passively receive a corresponding response.
**Security Analysis:**
Write-Single-Coil (function code 0x05) has a fixed-length PDU structure defined in Modbus specification Section 6.5: function code (1 byte) + Output Address (2 bytes) + Output Value (2 bytes) = exactly 5 bytes. The Output Value field is always exactly 2 bytes, with only two semantically valid values defined by the specification: 0xFF00 (coil ON) and 0x0000 (coil OFF). The specification explicitly states: "All other values are illegal and MUST NOT affect the coil." Compliant implementations handle this field with a simple two-way comparison (if value == 0xFF00 then ON, else if value == 0x0000 then OFF, else return Exception Response with code 0x03 Illegal Data Value). This is a constant-time, fixed-memory comparison operation with no dynamic buffer allocation, no arithmetic computation, and no loop iteration dependent on the field value. If the attacker sends an illegal value such as 0x1234, a compliant implementation returns an Exception Response and makes no state change; a non-compliant implementation may treat it as ON or OFF but still performs only a single-bit write to the coil data table. In no case does the Output Value field's content influence memory allocation sizes, array indices, or loop bounds. The field cannot trigger buffer overflows, integer arithmetic errors, or memory corruption regardless of the value chosen, because the processing path is a fixed comparison followed by a fixed-size single-bit write or an error response. While toggling a coil may affect a physical actuator (a concern under a different threat model), it cannot cause the protocol stack implementation to crash or exhibit undefined behavior.

**Classification:**
SAFE
