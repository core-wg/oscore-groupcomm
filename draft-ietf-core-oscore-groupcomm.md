---
title: Group OSCORE - Secure Group Communication for CoAP
abbrev: Group OSCORE
docname: draft-ietf-core-oscore-groupcomm-latest


# stand_alone: true

ipr: trust200902
area: Applications
wg: CoRE Working Group
kw: Internet-Draft
cat: std

coding: us-ascii
pi:    # can use array (if all yes) or hash here

  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
      -
        ins: M. Tiloca
        name: Marco Tiloca
        org: RISE AB
        street: Isafjordsgatan 22
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: marco.tiloca@ri.se
      -
        ins: G. Selander
        name: Goeran Selander
        org: Ericsson AB
        street: Torshamnsgatan 23
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: goran.selander@ericsson.com
      -
        ins: F. Palombini
        name: Francesca Palombini
        org: Ericsson AB
        street: Torshamnsgatan 23
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: francesca.palombini@ericsson.com
      -
        ins: J. Mattsson
        name: John Preuss Mattsson
        org: Ericsson AB
        street: Torshamnsgatan 23
        city: Kista
        code: SE-16440 Stockholm
        country: Sweden
        email: john.mattsson@ericsson.com
      -
        ins: J. Park
        name: Jiye Park
        org: Universitaet Duisburg-Essen
        street: Schuetzenbahn 70
        city: Essen
        code: 45127
        country: Germany
        email: ji-ye.park@uni-due.de

normative:

  I-D.ietf-core-groupcomm-bis:
  I-D.ietf-cose-rfc8152bis-struct:
  I-D.ietf-cose-rfc8152bis-algs:
  I-D.ietf-cose-countersign:
  RFC2119:
  RFC4086:
  RFC7252:
  RFC7748:
  RFC8032:
  RFC8174:
  RFC8613:
  RFC8949:
  COSE.Algorithms:
    author: 
      org: IANA
    date: false
    title: COSE Algorithms
    target: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  COSE.Key.Types:
    author: 
      org: IANA
    date: false
    title: COSE Key Types
    target: https://www.iana.org/assignments/cose/cose.xhtml#key-type
    
  NIST-800-56A:
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: A. Vassilev
        name: Apostol Vassilev
      -
        ins: R. Davis
        name: Richard Davis
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography - NIST Special Publication 800-56A, Revision 3
    date: 2018-04
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
    
informative:
  I-D.ietf-ace-key-groupcomm:
  I-D.ietf-ace-key-groupcomm-oscore:
  I-D.ietf-ace-oauth-authz:
  I-D.ietf-core-echo-request-tag:
  I-D.somaraju-ace-multicast:
  I-D.mattsson-cfrg-det-sigs-with-noise:
  I-D.ietf-lwig-security-protocol-comparison:
  I-D.tiloca-core-observe-multicast-notifications:
  I-D.ietf-lwig-curve-representations:
  I-D.ietf-tls-dtls13:
  RFC4944:
  RFC4949:
  RFC6282:
  RFC6347:
  RFC7228:
  RFC7641:
  RFC7959:
  Degabriele:
    author:
      -
        ins: J. P. Degabriele
        name: Jean Paul Degabriele
      -
        ins: A. Lehmann
        name: Anja Lehmann
      -
        ins: K. G. Paterson
        name: Kenneth G. Paterson
      -
        ins: N. P. Smart
        name: Nigel P. Smart
      -
        ins: M. Strefler
        name: Mario Strefler
    title: On the Joint Security of Encryption and Signature in EMV
    date: 2011-12
    target: https://eprint.iacr.org/2011/615

--- abstract

This document defines Group Object Security for Constrained RESTful Environments (Group OSCORE), providing end-to-end security of CoAP messages exchanged between members of a group, e.g. sent over IP multicast. In particular, the described approach defines how OSCORE is used in a group communication setting to provide source authentication for CoAP group requests, sent by a client to multiple servers, and for protection of the corresponding CoAP responses.

--- middle

# Introduction # {#intro}

The Constrained Application Protocol (CoAP) {{RFC7252}} is a web transfer protocol specifically designed for constrained devices and networks {{RFC7228}}. Group communication for CoAP {{I-D.ietf-core-groupcomm-bis}} addresses use cases where deployed devices benefit from a group communication model, for example to reduce latencies, improve performance and reduce bandwidth utilization. Use cases include lighting control, integrated building control, software and firmware updates, parameter and configuration updates, commissioning of constrained networks, and emergency multicast (see {{sec-use-cases}}). This specification defines the security protocol for Group communication for CoAP {{I-D.ietf-core-groupcomm-bis}}.

Object Security for Constrained RESTful Environments (OSCORE) {{RFC8613}} describes a security protocol based on the exchange of protected CoAP messages. OSCORE builds on CBOR Object Signing and Encryption (COSE) {{I-D.ietf-cose-rfc8152bis-struct}}{{I-D.ietf-cose-rfc8152bis-algs}} and provides end-to-end encryption, integrity, replay protection and binding of response to request between a sender and a recipient, independent of the transport layer also in the presence of intermediaries. To this end, a CoAP message is protected by including its payload (if any), certain options, and header fields in a COSE object, which replaces the authenticated and encrypted fields in the protected message.

This document defines Group OSCORE, providing the same end-to-end security properties as OSCORE in the case where CoAP requests have multiple recipients. In particular, the described approach defines how OSCORE is used in a group communication setting to provide source authentication for CoAP group requests, sent by a client to multiple servers, and for protection of the corresponding CoAP responses.

Just like OSCORE, Group OSCORE is independent of the transport layer and works wherever CoAP does. Group communication for CoAP {{I-D.ietf-core-groupcomm-bis}} uses UDP/IP multicast as the underlying data transport.

As with OSCORE, it is possible to combine Group OSCORE with communication security on other layers. One example is the use of transport layer security, such as DTLS {{RFC6347}}{{I-D.ietf-tls-dtls13}}, between one client and one proxy (and vice versa), or between one proxy and one server (and vice versa), in order to protect the routing information of packets from observers. Note that DTLS does not define how to secure messages sent over IP multicast.

Group OSCORE defines two modes of operation:

* In the group mode, Group OSCORE requests and responses are digitally signed with the private key of the sender and the signature is embedded in the protected CoAP message. The group mode supports all COSE algorithms as well as signature verification by intermediaries. This mode is defined in {{mess-processing}} and MUST be supported.

* In the pairwise mode, two group members exchange Group OSCORE requests and responses over unicast, and the messages are protected with symmetric keys. These symmetric keys are derived from Diffie-Hellman shared secrets, calculated with the asymmetric keys of the sender and recipient, allowing for shorter integrity tags and therefore lower message overhead. This mode is defined in {{sec-pairwise-protection}} and is OPTIONAL to support.

Both modes provide source authentication of CoAP messages. The application decides what mode to use, potentially on a per-message basis. Such decisions can be based, for instance, on pre-configured policies or dynamic assessing of the target recipient and/or resource, among other things. One important case is when requests are protected with the group mode, and responses with the pairwise mode. Since such responses convey shorter integrity tags instead of bigger, full-fledged signatures, this significantly reduces the message overhead in case of many responses to one request.

A special deployment of Group OSCORE is to use pairwise mode only. For example, consider the case of a constrained-node network {{RFC7228}} with a large number of CoAP endpoints and the objective to establish secure communication between any pair of endpoints with a small provisioning effort and message overhead. Since the total number of security associations that needs to be established grows with the square of the number of nodes, it is desirable to restrict the provisioned keying material. Moreover, a key establishment protocol would need to be executed for each security association. One solution to this is to deploy Group OSCORE, with the endpoints being part of a group, and use the pairwise mode. This solution assumes a trusted third party called Group Manager (see {{group-manager}}), but has the benefit of restricting the symmetric keying material while distributing only the public key of each group member. After that, a CoAP endpoint can locally derive the OSCORE Security Context for the other endpoint in the group, and protect CoAP communications with very low overhead {{I-D.ietf-lwig-security-protocol-comparison}}.

## Terminology ## {#terminology}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

Readers are expected to be familiar with the terms and concepts described in CoAP {{RFC7252}} including "endpoint", "client", "server", "sender" and "recipient"; group communication for CoAP {{I-D.ietf-core-groupcomm-bis}}; CBOR {{RFC8949}}; COSE {{I-D.ietf-cose-rfc8152bis-struct}}{{I-D.ietf-cose-rfc8152bis-algs}} and related counter signatures  {{I-D.ietf-cose-countersign}}.

Readers are also expected to be familiar with the terms and concepts for protection and processing of CoAP messages through OSCORE, such as "Security Context" and "Master Secret", defined in {{RFC8613}}.

Terminology for constrained environments, such as "constrained device" and "constrained-node network", is defined in {{RFC7228}}.

This document refers also to the following terminology.

* Keying material: data that is necessary to establish and maintain secure communication among endpoints. This includes, for instance, keys and IVs {{RFC4949}}.

* Group: a set of endpoints that share group keying material and security parameters (Common Context, see {{sec-context}}). That is, unless otherwise specified, the term group used in this specification refers to a "security group" (see Section 2.1 of {{I-D.ietf-core-groupcomm-bis}}), not to be confused with "CoAP group" or "application group".

* Group Manager: entity responsible for a group. Each endpoint in a group communicates securely with the respective Group Manager, which is neither required to be an actual group member nor to take part in the group communication. The full list of responsibilities of the Group Manager is provided in {{sec-group-manager}}.

* Silent server: member of a group that never sends protected responses in reply to requests. For CoAP group communications, requests are normally sent without necessarily expecting a response. A silent server may send unprotected responses, as error responses reporting an OSCORE error. Note that an endpoint can implement both a silent server and a client, i.e. the two roles are independent. An endpoint acting only as a silent server performs only Group OSCORE processing on incoming requests. Silent servers maintain less keying material and in particular do not have a Sender Context for the group. Since silent servers do not have a Sender ID, they cannot support the pairwise mode.

* Group Identifier (Gid): identifier assigned to the group, unique within the set of groups of a given Group Manager.

* Group request: CoAP request message sent by a client in the group to all servers in that group.

* Source authentication: evidence that a received message in the group originated from a specific identified group member. This also provides assurance that the message was not tampered with by anyone, be it a different legitimate group member or an endpoint which is not a group member.


# Security Context # {#sec-context}

This specification refers to a group as a set of endpoints sharing keying material and security parameters for executing the Group OSCORE protocol (see {{terminology}}). Each endpoint which is member of a group maintains a Security Context as defined in Section 3 of {{RFC8613}}, extended as follows (see {{fig-additional-context-information}}):

* One Common Context, shared by all the endpoints in the group. Two new parameters are included in the Common Context, namely Counter Signature Algorithm and Counter Signature Parameters. These relate to the computation of counter signatures, when messages are protected using the group mode (see {{mess-processing}}).

   If the pairwise mode is supported, the Common Context is further extended with two new parameters, namely Secret Derivation Algorithm and Secret Derivation Parameters. These relate to the derivation of a static-static Diffie-Hellman shared secret, from which pairwise keys are derived (see {{key-derivation-pairwise}}) to protect messages with the pairwise mode (see {{sec-pairwise-protection}}).

* One Sender Context, extended with the endpoint's private key. The private key is used to sign the message in group mode, and for deriving the pairwise keys in pairwise mode (see {{sec-derivation-pairwise}}). If the pairwise mode is supported, the Sender Context is also extended with the Pairwise Sender Keys associated to the other endpoints (see {{sec-derivation-pairwise}}). The Sender Context is omitted if the endpoint is configured exclusively as silent server. 

* One Recipient Context for each endpoint from which messages are received. It is not necessary to maintain Recipient Contexts associated to endpoints from which messages are not (expected to be) received. The Recipient Context is extended with the public key of the associated endpoint, used to verify the signature in group mode and for deriving the pairwise keys in pairwise mode (see {{sec-derivation-pairwise}}). If the pairwise mode is supported, then the Recipient Context is also extended with the Pairwise Recipient Key associated to the other endpoint (see {{sec-derivation-pairwise}}).

~~~~~~~~~~~
+-------------------+-----------------------------------------------+
| Context Component | New Information Elements                      |
+-------------------+-----------------------------------------------+
| Common Context    | Counter Signature Algorithm                   |
|                   | Counter Signature Parameters                  |
|                   | *Secret Derivation Algorithm                  |
|                   | *Secret Derivation Parameters                 |
+-------------------+-----------------------------------------------+
| Sender Context    | Endpoint's own private key                    |
|                   | *Pairwise Sender Keys for the other endpoints |
+-------------------+-----------------------------------------------+
| Each              | Public key of the other endpoint              |
| Recipient Context | *Pairwise Recipient Key of the other endpoint |
+-------------------+-----------------------------------------------+
~~~~~~~~~~~
{: #fig-additional-context-information title="Additions to the OSCORE Security Context. Optional additions are labeled with an asterisk." artwork-align="center"}

Further details about the Security Context of Group OSCORE are provided in the remainder of this section. How the Security Context is established by the group members is out of scope for this specification, but if there is more than one Security Context applicable to a message, then the endpoints MUST be able to tell which Security Context was latest established.

The default setting for how to manage information about the group is described in terms of a Group Manager (see {{group-manager}}).

## Common Context ## {#ssec-common-context}

The Common Context may be acquired from the Group Manager (see {{group-manager}}). The following sections define how the Common Context is extended, compared to {{RFC8613}}.

### ID Context ## {#ssec-common-context-id-context}

The ID Context parameter (see Sections 3.3 and 5.1 of {{RFC8613}}) in the Common Context SHALL contain the Group Identifier (Gid) of the group. The choice of the Gid format is application specific. An example of specific formatting of the Gid is given in {{gid-ex}}. The application needs to specify how to handle potential collisions between Gids (see {{ssec-gid-collision}}).

### Counter Signature Algorithm ## {#ssec-common-context-cs-alg}

Counter Signature Algorithm identifies the digital signature algorithm used to compute a counter signature on the COSE object (see Sections 3.2 and 3.3 of {{I-D.ietf-cose-countersign}}), when messages are protected using the group mode (see {{mess-processing}}).

This parameter is immutable once the Common Context is established. Counter Signature Algorithm MUST take value from the "Value" column of the "COSE Algorithms" Registry {{COSE.Algorithms}}. The value is associated to a COSE key type, as specified in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}}. COSE capabilities for algorithms are defined in Section 8 of {{I-D.ietf-cose-rfc8152bis-algs}}.

The EdDSA signature algorithm and the elliptic curve Ed25519 {{RFC8032}} are mandatory to implement. If elliptic curve signatures are used, it is RECOMMENDED to implement deterministic signatures with additional randomness as specified in {{I-D.mattsson-cfrg-det-sigs-with-noise}}.

### Counter Signature Parameters ## {#ssec-common-context-cs-params}

Counter Signature Parameters identifies the parameters associated to the digital signature algorithm specified in Counter Signature Algorithm. This parameter is immutable once the Common Context is established.

This parameter is a CBOR array including the following two elements, whose exact structure and value depend on the value of Counter Signature Algorithm:

* The first element is the array of COSE capabilities for Counter Signature Algorithm, as specified for that algorithm in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}} (see Section 8.1 of {{I-D.ietf-cose-rfc8152bis-algs}}).

* The second element is the array of COSE capabilities for the COSE key type associated to Counter Signature Algorithm, as specified for that key type in the "Capabilities" column of the "COSE Key Types" Registry {{COSE.Key.Types}} (see Section 8.2 of {{I-D.ietf-cose-rfc8152bis-algs}}).
   
Examples of Counter Signature Parameters are in {{sec-cs-params-ex}}.
   
This format is consistent with every counter signature algorithm currently considered in {{I-D.ietf-cose-rfc8152bis-algs}}, i.e. with algorithms that have only the COSE key type as their COSE capability. {{sec-future-cose-algs}} describes how Counter Signature Parameters can be generalized for possible future registered algorithms having a different set of COSE capabilities.
   
### Secret Derivation Algorithm ## {#ssec-common-context-dh-alg}

Secret Derivation Algorithm identifies the elliptic curve Diffie-Hellman algorithm used to derive a static-static Diffie-Hellman shared secret, from which pairwise keys are derived (see {{key-derivation-pairwise}}) to protect messages with the pairwise mode (see {{sec-pairwise-protection}}).

This parameter is immutable once the Common Context is established. Secret Derivation Algorithm MUST take value from the "Value" column of the "COSE Algorithms" Registry {{COSE.Algorithms}}. The value is associated to a COSE key type, as specified in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}}. COSE capabilities for algorithms are defined in Section 8 of {{I-D.ietf-cose-rfc8152bis-algs}}.

For endpoints that support the pairwise mode, the ECDH-SS + HKDF-256 algorithm specified in Section 6.3.1 of {{I-D.ietf-cose-rfc8152bis-algs}} and the X25519 curve {{RFC7748}} are mandatory to implement.

### Secret Derivation Parameters ## {#ssec-common-context-dh-params}

Secret Derivation Parameters identifies the parameters associated to the elliptic curve Diffie-Hellman algorithm specified in Secret Derivation Algorithm. This parameter is immutable once the Common Context is established.

This parameter is a CBOR array including the following two elements, whose exact structure and value depend on the value of Secret Derivation Algorithm:

* The first element is the array of COSE capabilities for Secret Derivation Algorithm, as specified for that algorithm in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}} (see Section 8.1 of {{I-D.ietf-cose-rfc8152bis-algs}}).

* The second element is the array of COSE capabilities for the COSE key type associated to Secret Derivation Algorithm, as specified for that key type in the "Capabilities" column of the "COSE Key Types" Registry {{COSE.Key.Types}} (see Section 8.2 of {{I-D.ietf-cose-rfc8152bis-algs}}).
   
Examples of Secret Derivation Parameters are in {{sec-cs-params-ex}}.

This format is consistent with every elliptic curve Diffie-Hellman algorithm currently considered in {{I-D.ietf-cose-rfc8152bis-algs}}, i.e. with algorithms that have only the COSE key type as their COSE capability. {{sec-future-cose-algs}} describes how Secret Derivation Parameters can be generalized for possible future registered algorithms having a different set of COSE capabilities.

## Sender Context and Recipient Context ## {#ssec-sender-recipient-context}

OSCORE specifies the derivation of Sender Context and Recipient Context, specifically of Sender/Recipient Keys and Common IV, from a set of input parameters (see Section 3.2 of {{RFC8613}}). This derivation applies also to Group OSCORE, and the mandatory-to-implement HKDF and AEAD algorithms are the same as in {{RFC8613}}. The Sender ID SHALL be unique for each endpoint in a group with a fixed Master Secret, Master Salt and Group Identifier (see Section 3.3 of {{RFC8613}}).

For Group OSCORE, the Sender Context and Recipient Context additionally contain asymmetric keys, as described previously in {{sec-context}}. The private/public key pair of the sender can, for example, be generated by the endpoint or provisioned during manufacturing. 

With the exception of the public key of the sender endpoint and the possibly associated pairwise keys, a receiver endpoint can derive a complete Security Context from a received Group OSCORE message and the Common Context. The public keys in the Recipient Contexts can be retrieved from the Group Manager (see {{group-manager}}) upon joining the group. A public key can alternatively be acquired from the Group Manager at a later time, for example the first time a message is received from a particular endpoint in the group (see {{ssec-verify-request}} and {{ssec-verify-response}}).

For severely constrained devices, it may be not feasible to simultaneously handle the ongoing processing of a recently received message in parallel with the retrieval of the sender endpoint's public key. Such devices can be configured to drop a received message for which there is no (complete) Recipient Context, and retrieve the sender endpoint's public key in order to have it available to verify subsequent messages from that endpoint.

An endpoint admits a maximum amount of Recipient Contexts for a same Security Context, e.g. due to memory limitations. After reaching that limit, the creation of a new Recipient Context results in an overflow. When this happens, the endpoint has to delete a current Recipient Context to install the new one. It is up to the application to define policies for selecting the current Recipient Context to delete. A newly installed Recipient Context that has required to delete another Recipient Context is initialized with an invalid Replay Window, and accordingly requires the endpoint to take appropriate actions (see {{ssec-loss-mutable-context-overflow}}).

## Pairwise Keys ## {#sec-derivation-pairwise}

Certain signature schemes, such as EdDSA and ECDSA, support a secure combined signature and encryption scheme. This section specifies the derivation of "pairwise keys", for use in the pairwise mode defined in {{sec-pairwise-protection}}.

### Derivation of Pairwise Keys ### {#key-derivation-pairwise}

Using the Group OSCORE Security Context (see {{sec-context}}), a group member can derive AEAD keys to protect point-to-point communication between itself and any other endpoint in the group. The same AEAD algorithm as in the group mode is used. The key derivation of these so-called pairwise keys follows the same construction as in Section 3.2.1 of {{RFC8613}}: 

~~~~~~~~~~~
Pairwise Sender Key    = HKDF(Sender Key, Shared Secret, info, L)
Pairwise Recipient Key = HKDF(Recipient Key, Shared Secret, info, L)
~~~~~~~~~~~

where:

* The Pairwise Sender Key is the AEAD key for processing outgoing messages addressed to endpoint X. 

* The Pairwise Recipient Key is the AEAD key for processing incoming messages from endpoint X.

* HKDF is the HKDF algorithm specified by Secret Derivation Algorithm from the Common Context (see {{ssec-common-context-dh-alg}}).

* The Sender Key and private key are from the Sender Context. The Sender Key is used as salt in the HKDF, when deriving the Pairwise Sender Key.

* The Recipient Key and the public key are from the Recipient Context associated to endpoint X. The Recipient Key is used as salt in the HKDF, when deriving the Pairwise Recipient Key.
 
* The Shared Secret is computed as a static-static Diffie-Hellman shared secret {{NIST-800-56A}}, where the endpoint uses its private key and the public key of the other endpoint X. The Shared Secret is used as Input Keying Material (IKM) in the HKDF.

* info and L are as defined in Section 3.2.1 of {{RFC8613}}. 

If EdDSA asymmetric keys are used, the Edward coordinates are mapped to Montgomery coordinates using the maps defined in Sections 4.1 and 4.2 of {{RFC7748}}, before using the X25519 and X448 functions defined in Section 5 of {{RFC7748}}.

After establishing a partially or completely new Security Context (see {{ssec-sec-context-persistence}} and {{sec-group-key-management}}), the old pairwise keys MUST be deleted. Since new Sender/Recipient Keys are derived from the new group keying material (see {{ssec-sender-recipient-context}}), every group member MUST use the new Sender/Recipient Keys when deriving new pairwise keys.

As long as any two group members preserve the same asymmetric keys, their Diffie-Hellman shared secret does not change across updates of the group keying material.

### Usage of Sequence Numbers ### {#pairwise-seqno}

When using any of its Pairwise Sender Keys, a sender endpoint including the 'Partial IV' parameter in the protected message MUST use the current fresh value of the Sender Sequence Number from its Sender Context (see {{ssec-sender-recipient-context}}). That is, the same Sender Sequence Number space is used for all outgoing messages protected with Group OSCORE, thus limiting both storage and complexity.

On the other hand, when combining group and pairwise communication modes, this may result in the Partial IV values moving forward more often. This can happen when a client engages in frequent or long sequences of one-to-one exchanges with servers in the group, by sending requests over unicast.

### Security Context for Pairwise Mode  ### {#pairwise-implementation}

If the pairwise mode is supported, the Security Context additionally includes Secret Derivation Algorithm, Secret Derivation Parameters and the pairwise keys, as described at the beginning of {{sec-context}}.
 
The pairwise keys as well as the shared secrets used in their derivation (see {{key-derivation-pairwise}}) may be stored in memory or recomputed every time they are needed. The shared secret changes only when a public/private key pair used for its derivation changes, which results in the pairwise keys also changing. Additionally, the pairwise keys change if the Sender ID changes or if a new Security Context is established for the group (see {{sec-group-re-join}}). In order to optimize protocol performance, an endpoint may store the derived pairwise keys for easy retrieval. 

In the pairwise mode, the Sender Context includes the Pairwise Sender Keys to use with the other endpoints (see {{fig-additional-context-information}}). In order to identify the right key to use, the Pairwise Sender Key for endpoint X may be associated to the Recipient ID of endpoint X, as defined in the Recipient Context (i.e. the Sender ID from the point of view of endpoint X). In this way, the Recipient ID can be used to lookup for the right Pairwise Sender Key. This association may be implemented in different ways, e.g. by storing the pair (Recipient ID, Pairwise Sender Key) or linking a Pairwise Sender Key to a Recipient Context.

## Update of Security Context {#ssec-sec-context-persistence} 

It is RECOMMENDED that the immutable part of the Security Context is stored in non-volatile memory, or that it can otherwise be reliably accessed throughout the operation of the group, e.g. after a device reboots. However, also immutable parts of the Security Context may need to be updated, for example due to scheduled key renewal, new or re-joining members in the group, or the fact that the endpoint changes Sender ID (see {{sec-group-re-join}}).

On the other hand, the mutable parts of the Security Context are updated by the endpoint when executing the security protocol, but may nevertheless become outdated, e.g. due to loss of the mutable Security Context (see {{ssec-loss-mutable-context}}) or exhaustion of Sender Sequence Numbers (see {{ssec-wrap-around-partial-iv}}).

If it is not feasible or practically possible to store and maintain up-to-date the mutable part in non-volatile memory (e.g., due to limited number of write operations), the endpoint MUST be able to detect a loss of the mutable Security Context and MUST accordingly take the actions defined in {{ssec-loss-mutable-context}}.

### Loss of Mutable Security Context {#ssec-loss-mutable-context}

<!-- MT 2020-10-12: This is now partly overriden, since the rebooted endpoint has to contact the Group Manager for help. Then, either it gets a new Sender ID, or the whole group is rekeyed. In either case, the endpoint resets its Sender Sequence Number to 0 and derives a new Sender Key.

An endpoint losing its mutable Security Context, e.g., due to reboot, needs to prevent the re-use of Sender Sequence Numbers, and to handle incoming replayed messages. Appendix B.1 of {{RFC8613}} describes secure procedures for handling the loss of Sender Sequence Number and the update of Replay Window. The procedure in Appendix B.1.1 of {{RFC8613}} applies also to servers in Group OSCORE and is RECOMMENDED to use. A variant of Appendix B.1.2 of {{RFC8613}} applicable to Group OSCORE is specified in {{sec-synch-challenge-response}} of this specification.
-->

An endpoint may lose its mutable Security Context, e.g. due to a reboot (see {{ssec-loss-mutable-context-total}}) or to an overflow of Recipient Contexts (see {{ssec-loss-mutable-context-overflow}}).

In such a case, the endpoint needs to prevent the re-use of a nonce with the same AEAD key, and to handle incoming replayed messages.

#### Reboot and Total Loss {#ssec-loss-mutable-context-total}

In case a loss of the Sender Context and/or of the Recipient Contexts is detected (e.g. following a reboot), the endpoint MUST NOT protect further messages using this Security Context to avoid reusing an AEAD nonce with the same AEAD key.

In particular, before resuming its operations in the group, the endpoint MUST retrieve new Security Context parameters from the Group Manager (see {{sec-group-re-join}}) and use them to derive a new Sender Context (see {{ssec-sender-recipient-context}}). Since this includes a newly derived Sender Key, the server will not reuse the same pair (key, nonce), even when using the Partial IV of (old re-injected) requests to build the AEAD nonce for protecting the corresponding responses.

From then on, the endpoint MUST use the latest installed Sender Context to protect outgoing messages. Also, newly created Recipient Contexts will have a Replay Window which is initialized as valid.

If not able to establish an updated Sender Context, e.g. because of lack of connectivity with the Group Manager, the endpoint MUST NOT protect further messages using the current Security Context and MUST NOT accept incoming messages from other group members, as currently unable to detect possible replays.

#### Overflow of Recipient Contexts {#ssec-loss-mutable-context-overflow}

After reaching the maximum amount of Recipient Contexts, an endpoint will experience an overflow when installing a new Recipient Context, as it requires to first delete an existing one (see {{ssec-sender-recipient-context}}).

Every time this happens, the Replay Window of the new Recipient Context is initialized as not valid. Therefore, the endpoint MUST take the following actions, before accepting request messages from the client associated to the new Recipient Context.

If it is not configured as silent server, the endpoint MUST either:

* Retrieve new Security Context parameters from the Group Manager and derive a new Sender Context, as defined in {{ssec-loss-mutable-context-total}}; or

* When receiving a first request to process with the new Recipient Context, use the approach specified in {{sec-synch-challenge-response}} and based on the Echo Option for CoAP {{I-D.ietf-core-echo-request-tag}}, if supported. In particular, the endpoint MUST use its Partial IV when generating the AEAD nonce and MUST include the Partial IV in the response message conveying the Echo Option. If the endpoint supports the CoAP Echo Option, it is RECOMMENDED to take this approach.

If it is configured exclusively as silent server, the endpoint MUST wait for the next group rekeying to occur, in order to derive a new Security Context and re-initialize the Replay Window of each Recipient Contexts as valid.

### Exhaustion of Sender Sequence Number {#ssec-wrap-around-partial-iv}

An endpoint can eventually exhaust the Sender Sequence Number, which is incremented for each new outgoing message including a Partial IV. This is the case for group requests, Observe notifications {{RFC7641}} and, optionally, any other response.

Implementations MUST be able to detect an exhaustion of Sender Sequence Number, after the endpoint has consumed the largest usable value. If an implementation's integers support wrapping addition, the implementation MUST treat Sender Sequence Number as exhausted when a wrap-around is detected.

Upon exhausting the Sender Sequence Numbers, the endpoint MUST NOT use this Security Context to protect further messages including a Partial IV.

The endpoint SHOULD inform the Group Manager, retrieve new Security Context parameters from the Group Manager (see {{sec-group-re-join}}), and use them to derive a new Sender Context (see {{ssec-sender-recipient-context}}).

From then on, the endpoint MUST use its latest installed Sender Context to protect outgoing messages.

### Retrieving New Security Context Parameters {#sec-group-re-join}

The Group Manager can assist an endpoint with an incomplete Sender Context to retrieve missing data of the Security Context and thereby become fully operational in the group again. The two main options for the Group Manager are described in this section: i) assignment of a new Sender ID to the endpoint (see {{new-sender-id}}); and ii) establishment of a new Security Context for the group (see {{new-sec-context}}). The update of the Replay Window in each of the Recipient Contexts is discussed in {{sec-synch-seq-num}}.

As group membership changes, or as group members get new Sender IDs (see {{new-sender-id}}) so do the relevant Recipient IDs that the other endpoints need to keep track of. As a consequence, group members may end up retaining stale Recipient Contexts, that are no longer useful to verify incoming secure messages. 

The Recipient ID ('kid') SHOULD NOT be considered as a persistent and reliable indicator of a group member. Such an indication can be achieved only by using that member's public key, when verifying countersignatures of received messages (in group mode), or when verifying messages integrity-protected with pairwise keying material derived from asymmetric keys (in pairwise mode).

Furthermore, applications MAY define policies to: i) delete (long-)unused Recipient Contexts and reduce the impact on storage space; as well as ii) check with the Group Manager that a public key is currently the one associated to a 'kid' value, after a number of consecutive failed verifications.

#### New Sender ID for the Endpoint {#new-sender-id}

The Group Manager may assign a new Sender ID to an endpoint, while leaving the Gid, Master Secret and Master Salt unchanged in the group. In this case, the Group Manager MUST assign a Sender ID that has never been assigned before in the group under the current Gid value.

Having retrieved the new Sender ID, and potentially other missing data of the immutable Security Context, the endpoint can derive a new Sender Context (see {{ssec-sender-recipient-context}}). When doing so, the endpoint resets the Sender Sequence Number in its Sender Context to 0, and derives a new Sender Key. This is in turn used to possibly derive new Pairwise Sender Keys.

From then on, the endpoint MUST use its latest installed Sender Context to protect outgoing messages.

The assignment of a new Sender ID may be the result of different processes. The endpoint may request a new Sender ID, e.g. because of exhaustion of Sender Sequence Numbers (see {{ssec-wrap-around-partial-iv}}). An endpoint may request to re-join the group, e.g. because of losing its mutable Security Context (see {{ssec-loss-mutable-context}}), and is provided with a new Sender ID together with the latest immutable Security Context.

For the other group members, the Recipient Context corresponding to the old Sender ID becomes stale (see {{sec-group-key-management}}).

#### New Security Context for the Group {#new-sec-context}

The Group Manager may establish a new Security Context for the group (see {{sec-group-key-management}}). The Group Manager does not necessarily establish a new Security Context for the group if one member has an outdated Security Context (see {{new-sender-id}}), unless that was already planned or required for other reasons.

All the group members need to acquire new Security Context parameters from the Group Manager. Once having acquired new Security Context parameters, each group member performs the following actions.

* From then on, it MUST NOT use the current Security Context to start processing new messages for the considered group.

* It completes any ongoing message processing for the considered group.

* It derives and install a new Security Context. In particular:

   - It re-derives the keying material stored in its Sender Context and Recipient Contexts (see {{ssec-sender-recipient-context}}). The Master Salt used for the re-derivations is the updated Master Salt parameter if provided by the Group Manager, or the empty byte string otherwise.

   - It resets to 0 its Sender Sequence Number in its Sender Context.

   - It re-initializes the Replay Window of each Recipient Context.

   - It resets to 0 the sequence number of each ongoing observation where it is an observer client and that it wants to keep active.

From then on, it can resume processing new messages for the considered group. In particular:

* It MUST use its latest installed Sender Context to protect outgoing messages.
   
* It SHOULD use its latest installed Recipient Contexts to process incoming messages, unless application policies admit to temporarily retain and use the old, recent, Security Context (see {{ssec-key-rotation-late-sender}}).

The distribution of a new Gid and Master Secret may result in temporarily misaligned Security Contexts among group members. In particular, this may result in a group member not being able to process messages received right after a new Gid and Master Secret have been distributed. A discussion on practical consequences and possible ways to address them, as well as on how to handle the old Security Context, is provided in {{ssec-key-rotation}}.


# The Group Manager # {#group-manager}

As with OSCORE, endpoints communicating with Group OSCORE need to establish the relevant Security Context. Group OSCORE endpoints need to acquire OSCORE input parameters, information about the group(s) and about other endpoints in the group(s). This specification is based on the existence of an entity called Group Manager which is responsible for the group, but does not mandate how the Group Manager interacts with the group members. The responsibilities of the Group Manager are compiled in {{sec-group-manager}}.

It is RECOMMENDED to use a Group Manager as described in {{I-D.ietf-ace-key-groupcomm-oscore}}, where the join process is based on the ACE framework for authentication and authorization in constrained environments {{I-D.ietf-ace-oauth-authz}}.

The Group Manager assigns unique Group Identifiers (Gids) to different groups under its control, as well as unique Sender IDs (and thereby Recipient IDs) to the members of those groups. According to a hierarchical approach, the Gid value assigned to a group is associated to a dedicated space for the values of Sender ID and Recipient ID of the members of that group.

The Group Manager MUST NOT reassign a Gid value to the same group, and MUST NOT reassign a Sender ID within the same group under the same Gid value.

In addition, the Group Manager maintains records of the public keys of endpoints in a group, and provides information about the group and its members to other group members and selected roles. Upon nodes' joining, the Group Manager collects such public keys and MUST verify proof-of-possession of the respective private key.

An endpoint acquires group data such as the Gid and OSCORE input parameters including its own Sender ID from the Group Manager, and provides information about its public key to the Group Manager, for example upon joining the group. 

A group member can retrieve from the Group Manager the public key and other information associated to another member of the group, with which it can generate the corresponding Recipient Context. In particular, the requested public key is provided together with the Sender ID of the associated group member. An application can configure a group member to asynchronously retrieve information about Recipient Contexts, e.g. by Observing {{RFC7641}} a resource at the Group Manager to get updates on the group membership.

The Group Manager MAY serve additional entities acting as signature checkers, e.g. intermediary gateways. These entities do not join a group as members, but can retrieve public keys of group members from the Group Manager, in order to verify counter signatures of group messages. A signature checker MUST be authorized for retrieving public keys of members in a specific group from the Group Manager. To this end, the same method mentioned above based on the ACE framework {{I-D.ietf-ace-oauth-authz}} can be used.

## Management of Group Keying Material # {#sec-group-key-management}

In order to establish a new Security Context for a group, a new Group Identifier (Gid) for that group and a new value for the Master Secret parameter MUST be generated. When distributing the new Gid and Master Secret, the Group Manager MAY distribute also a new value for the Master Salt parameter, and should preserve the current value of the Sender ID of each group member.

The Group Manager MUST NOT reassign a Gid value to the same group. That is, every group can have a given Gid at most once during its lifetime. An example of Gid format supporting this operation is provided in {{gid-ex}}.

The Group Manager MUST NOT reassign a previously used Sender ID ('kid') with the same Gid, Master Secret and Master Salt. That is, the Group Manager MUST NOT reassign a Sender ID value within a same group under the same Gid value (see {{new-sender-id}}). Within this restriction, the Group Manager can assign a Sender ID used under an old Gid value, thus avoiding Sender ID values to irrecoverably grow in size.

Even when an endpoint joining a group is recognized as a current member of that group, e.g. through the ongoing secure communication association, the Group Manager MUST assign a new Sender ID different than the one currently used by the endpoint in the group, unless the group is rekeyed first and a new Gid value is established.

{{fig-key-material-diagram}} overviews the different keying material components, considering their relation and possible reuse across group rekeying.

~~~~~~~~~~~
Components changed in lockstep            * Changing a kid does not
    upon a group rekeying                   need changing the Group ID
+----------------------------+
|                            |            * A kid is not reassigned
| Master               Group |<--> kid1     under the same Group ID
| Secret <---> o <--->  ID   |
|              ^             |<--> kid2   * Upon changing the Group ID,
|              |             |              every current kid should
|              |             |<--> kid3     be preserved for efficient
|              v             |              key rollover
|         Master Salt        | ... ...   
|         (optional)         |            * After changing Group ID, an
|                            |              unused kid can be assigned
+----------------------------+
~~~~~~~~~~~
{: #fig-key-material-diagram title="Relations among keying material components." artwork-align="center"}

If required by the application (see {{ssec-sec-assumptions}}), it is RECOMMENDED to adopt a group key management scheme, and securely distribute a new value for the Gid and for the Master Secret parameter of the group's Security Context, before a new joining endpoint is added to the group or after a currently present endpoint leaves the group. This is necessary to preserve backward security and forward security in the group, if the application requires it.

The specific approach used to distribute new group data is out of the scope of this document. However, it is RECOMMENDED that the Group Manager supports the distribution of the new Gid and Master Secret parameter to the group according to the Group Rekeying Process described in {{I-D.ietf-ace-key-groupcomm-oscore}}.


## Responsibilities of the Group Manager ## {#sec-group-manager}

The Group Manager is responsible for performing the following tasks:

1. Creating and managing OSCORE groups. This includes the assignment of a Gid to every newly created group, as well as ensuring uniqueness of Gids within the set of its OSCORE groups.

2. Defining policies for authorizing the joining of its OSCORE groups.

3. Handling the join process to add new endpoints as group members.

4. Establishing the Common Context part of the Security Context, and providing it to authorized group members during the join process, together with the corresponding Sender Context.

5. Updating the Gid of its OSCORE groups, upon renewing the respective Security Context. This includes ensuring that the same Gid value is not reassigned to the same group.

6. Generating and managing Sender IDs within its OSCORE groups, as well as assigning and providing them to new endpoints during the join process, or to current group members upon request of renewal or re-joining.

   This includes ensuring that each Sender ID: is unique within each of the OSCORE groups; and is not reassigned within the same group under the same Gid value, i.e. not even to a current group member re-joining the same group without a rekeying happening first.

7. Defining communication policies for each of its OSCORE groups, and signaling them to new endpoints during the join process.

8. Renewing the Security Context of an OSCORE group upon membership change, by revoking and renewing common security parameters and keying material (rekeying).

9. Providing the management keying material that a new endpoint requires to participate in the rekeying process, consistently with the key management scheme used in the group joined by the new endpoint.

10. Acting as key repository, in order to handle the public keys of the members of its OSCORE groups, and providing such public keys to other members of the same group upon request. The actual storage of public keys may be entrusted to a separate secure storage device or service.

11. Validating that the format and parameters of public keys of group members are consistent with the countersignature algorithm and related parameters used in the respective OSCORE group.

The Group Manager described in {{I-D.ietf-ace-key-groupcomm-oscore}} provides these functionalities.


# The COSE Object # {#sec-cose-object}

Building on Section 5 of {{RFC8613}}, this section defines how to use COSE {{I-D.ietf-cose-rfc8152bis-struct}} to wrap and protect data in the original message. OSCORE uses the untagged COSE_Encrypt0 structure with an Authenticated Encryption with Associated Data (AEAD) algorithm. Unless otherwise specified, the following modifications apply for both the group mode and the pairwise mode of Group OSCORE.

## Counter Signature # {#sec-cose-object-unprotected-field}

When protecting a message in group mode, the 'unprotected' field MUST additionally include the following parameter:

* COSE_CounterSignature0: its value is set to the counter signature of the COSE object, computed by the sender as described in Sections 3.2 and 3.3 of {{I-D.ietf-cose-countersign}}, by using its private key and according to the Signature Algorithm in the Security Context.

   In particular, the Countersign_structure contains the context text string "CounterSignature0", the external_aad as defined in {{sec-cose-object-ext-aad}} of this specification, and the ciphertext of the COSE object as payload.

## The 'kid' and 'kid context' parameters # {#sec-cose-object-kid}

The value of the 'kid' parameter in the 'unprotected' field of response messages MUST be set to the Sender ID of the endpoint transmitting the message, if the request was protected in group mode. That is, unlike in {{RFC8613}}, the 'kid' parameter is always present in responses to a request that was protected in group mode.

The value of the 'kid context' parameter in the 'unprotected' field of requests messages MUST be set to the ID Context, i.e. the Group Identifier value (Gid) of the group. That is, unlike in {{RFC8613}}, the 'kid context' parameter is always present in requests.

## external_aad # {#sec-cose-object-ext-aad}

The external_aad of the Additional Authenticated Data (AAD) is different compared to OSCORE, and is defined in this section.

The same external_aad structure is used in group mode and pairwise mode for encryption (see Section 5.3 of {{I-D.ietf-cose-rfc8152bis-struct}}), as well as in group mode for signing (see Section 4.4 of {{I-D.ietf-cose-rfc8152bis-struct}}).

In particular, the external_aad includes also the signature algorithm, the value of the 'kid context' in the COSE object of the request, and the OSCORE option of the protected message.

~~~~~~~~~~~ CDDL
external_aad = bstr .cbor aad_array

aad_array = [
   oscore_version : uint,
   algorithms : [alg_aead : int / tstr,
                 alg_signature : int / tstr / null,
                 alg_signature_aead : int / tstr / null,
                 alg_pairwise_key_agreement : int / tstr / null]
   request_kid : bstr,
   request_piv : bstr,
   options : bstr,
   request_kid_context : bstr,
   OSCORE_option: bstr,
   sender_pk: any,
]
~~~~~~~~~~~
{: #fig-ext-aad title="external_aad" artwork-align="center"}

Compared with Section 5.4 of {{RFC8613}}, the aad_array has the following differences.

* The 'algorithms' array additionally includes:

   - 'alg_signature', which specifies Signature Algorithm from the Common Context (see {{ssec-common-context-cs-alg}}). This parameter MUST encode the value of Signature Algorithm as a CBOR integer or text string, consistently with the "Value" field in the "COSE Algorithms" Registry for this signature algorithm.

   - 'alg_signature_aead', which specifies Signature AEAD Algorithm from the Common Context (see {{ssec-common-context-cs-alg}}). This parameter MUST encode the value of Signature AEAD Algorithm as a CBOR integer or text string, consistently with the "Value" field in the "COSE Algorithms" Registry for this AEAD algorithm.

   - 'alg_pairwise_key_agreement', which specifies Pairwise KDF Algorithm from the Common Context (see {{ssec-common-context-cs-alg}}). This parameter MUST encode the value of Pairwise Key Agreement Algorithm as a CBOR integer or text string, consistently with the "Value" field in the "COSE Algorithms" Registry for this KDF algorithm.
   
* The new element 'request_kid_context' contains the value of the 'kid context' in the COSE object of the request (see {{sec-cose-object-kid}}).

   In case Observe {{RFC7641}} is used, this enables endpoints to safely keep an observation active beyond a possible change of Gid, i.e. of ID Context, following a group rekeying (see {{sec-group-key-management}}). In fact, it ensures that every notification cryptographically matches with only one observation request, rather than with multiple ones that were protected with different keying material but share the same 'request_kid' and 'request_piv' values.

* The new element 'OSCORE_option', containing the value of the OSCORE Option present in the protected message, encoded as a binary string.

* The new element 'sender_pk', containing the sender's public key. An X.509 certificates are byte strings, C509 certificates and CWTs are arrays but might be tagged.

   Note for implementation: this construction requires the OSCORE option of the message to be generated and finalized before computing the ciphertext of the COSE_Encrypt0 object (when using the group mode or the pairwise mode) and before calculating the counter signature (when using the group mode). Also, the aad_array needs to be large enough to contain the largest possible OSCORE option.

# OSCORE Header Compression {#compression}

The OSCORE header compression defined in Section 6 of {{RFC8613}} is used, with the following differences.

* The payload of the OSCORE message SHALL encode the ciphertext of the COSE_Encrypt0 object. In the group mode, the ciphertext above is concatenated with the value of the COSE_CounterSignature0 of the COSE object, computed as described in {{sec-cose-object-unprotected-field}}.

* This specification defines the usage of the sixth least significant bit, called "Group Flag", in the first byte of the OSCORE option containing the OSCORE flag bits. This flag bit is specified in {{iana-cons-flag-bits}}.

* The Group Flag MUST be set to 1 if the OSCORE message is protected using the group mode (see {{mess-processing}}). 

* The Group Flag MUST be set to 0 if the OSCORE message is protected using the pairwise mode (see {{sec-pairwise-protection}}). The Group Flag MUST also be set to 0 for ordinary OSCORE messages processed according to {{RFC8613}}.
    
## Examples of Compressed COSE Objects

This section covers a list of OSCORE Header Compression examples of Group OSCORE used in group mode (see {{sssec-example-cose-group}}) or in pairwise mode (see {{sssec-example-cose-pairwise}}).

The examples assume that the COSE_Encrypt0 object is set (which means the CoAP message and cryptographic material is known). Note that the examples do not include the full CoAP unprotected message or the full Security Context, but only the input necessary to the compression mechanism, i.e. the COSE_Encrypt0 object. The output is the compressed COSE object as defined in {{compression}} and divided into two parts, since the object is transported in two CoAP fields: OSCORE option and payload.

The examples assume that the plaintext (see Section 5.3 of {{RFC8613}}) is 6 bytes long, and that the AEAD tag is 8 bytes long, hence resulting in a ciphertext which is 14 bytes long. When using the group mode, the COSE_CounterSignature0 byte string as described in {{sec-cose-object}} is assumed to be 64 bytes long.

### Examples in Group Mode ## {#sssec-example-cose-group}

* Request with ciphertext = 0xaea0155667924dff8a24e4cb35b9, kid = 0x25, Partial IV = 5 and kid context = 0x44616c.

~~~~~~~~~~~
   * Before compression (96 bytes):

      [
      h'',
      { 4:h'25', 6:h'05', 10:h'44616c', 11:h'de9e ... f1' },
      h'aea0155667924dff8a24e4cb35b9'
      ]
~~~~~~~~~~~

~~~~~~~~~~~
   * After compression (85 bytes):

      Flag byte: 0b00111001 = 0x39 (1 byte)

      Option Value: 0x39 05 03 44 61 6c 25 (7 bytes)

      Payload: 0xaea0155667924dff8a24e4cb35b9 de9e ... f1
      (14 bytes + size of the counter signature)

~~~~~~~~~~~


* Response with ciphertext = 0x60b035059d9ef5667c5a0710823b, kid = 0x52 and no Partial IV.

~~~~~~~~~~~
   * Before compression (88 bytes):

      [
      h'',
      { 4:h'52', 11:h'ca1e ... b3' },
      h'60b035059d9ef5667c5a0710823b'
      ]
~~~~~~~~~~~

~~~~~~~~~~~
   * After compression (80 bytes):

      Flag byte: 0b00101000 = 0x28 (1 byte)

      Option Value: 0x28 52 (2 bytes)

      Payload: 0x60b035059d9ef5667c5a0710823b ca1e ... b3
      (14 bytes + size of the counter signature)
~~~~~~~~~~~

### Examples in Pairwise Mode ## {#sssec-example-cose-pairwise}

* Request with ciphertext = 0xaea0155667924dff8a24e4cb35b9, kid = 0x25, Partial IV = 5 and kid context = 0x44616c.

~~~~~~~~~~~
   * Before compression (29 bytes):

      [
      h'',
      { 4:h'25', 6:h'05', 10:h'44616c' },
      h'aea0155667924dff8a24e4cb35b9'
      ]
~~~~~~~~~~~

~~~~~~~~~~~
   * After compression (21 bytes):

      Flag byte: 0b00011001 = 0x19 (1 byte)

      Option Value: 0x19 05 03 44 61 6c 25 (7 bytes)

      Payload: 0xaea0155667924dff8a24e4cb35b9 (14 bytes)
~~~~~~~~~~~


* Response with ciphertext = 0x60b035059d9ef5667c5a0710823b and no Partial IV.

~~~~~~~~~~~
   * Before compression (18 bytes):

      [
      h'',
      {},
      h'60b035059d9ef5667c5a0710823b'
      ]
~~~~~~~~~~~

~~~~~~~~~~~
   * After compression (14 bytes):

      Flag byte: 0b00000000 = 0x00 (1 byte)

      Option Value: 0x (0 bytes)

      Payload: 0x60b035059d9ef5667c5a0710823b (14 bytes)
~~~~~~~~~~~

# Message Binding, Sequence Numbers, Freshness and Replay Protection

The requirements and properties described in Section 7 of {{RFC8613}} also apply to Group OSCORE. In particular, Group OSCORE provides message binding of responses to requests, which enables absolute freshness of responses that are not notifications, relative freshness of requests and notification responses, and replay protection of requests. In addition, the following holds for Group OSCORE.

## Update of Replay Window # {#sec-synch-seq-num}

Sender Sequence Numbers seen by a server as Partial IV values in request messages can spontaneously increase at a fast pace, for example when a client exchanges unicast messages with other servers using the Group OSCORE Security Context. As in OSCORE {{RFC8613}}, a server always needs to accept such increases and accordingly updates the Replay Window in each of its Recipient Contexts.

As discussed in {{ssec-loss-mutable-context}}, a newly created Recipient Context would have an invalid Replay Window, if its installation has required to delete another Recipient Context. Hence, the server is not able to verify if a request from the client associated to the new Recipient Context is a replay. When this happens, the server MUST validate the Replay Window of the new Recipient Context, before accepting messages from the associated client (see {{ssec-loss-mutable-context}}).

Furthermore, when the Group Manager establishes a new Security Context for the group (see {{new-sec-context}}), every server re-initializes the Replay Window in each of its Recipient Contexts.

## Message Freshness # {#sec-freshness}

When receiving a request from a client for the first time, the server is not synchronized with the client's Sender Sequence Number, i.e. it is not able to verify if that request is fresh. This applies to a server that has just joined the group, with respect to already present clients, and recurs as new clients are added as group members.

During its operations in the group, the server may also lose synchronization with a client's Sender Sequence Number. This can happen, for instance, if the server has rebooted or has deleted its previously synchronized version of the Recipient Context for that client (see {{ssec-loss-mutable-context}}).

If the application requires message freshness, e.g. according to time- or event-based policies, the server has to (re-)synchronize with a client's Sender Sequence Number before delivering request messages from that client to the application. To this end, the server can use the approach in {{sec-synch-challenge-response}} based on the Echo Option for CoAP {{I-D.ietf-core-echo-request-tag}}, as a variant of the approach defined in Appendix B.1.2 of {{RFC8613}} applicable to Group OSCORE.

# Message Reception # {#sec-message-reception}

Upon receiving a protected message, a recipient endpoint retrieves a Security Context as in {{RFC8613}}. An endpoint MUST be able to distinguish between a Security Context to process OSCORE messages as in {{RFC8613}} and a Group OSCORE Security Context to process Group OSCORE messages as defined in this specification.

To this end, an endpoint can take into account the different structure of the Security Context defined in {{sec-context}}, for example based on the presence of Counter Signature Algorithm in the Common Context. Alternatively implementations can use an additional parameter in the Security Context, to explicitly signal that it is intended for processing Group OSCORE messages.

If either of the following two conditions holds, a recipient endpoint MUST discard the incoming protected message:
   
   - The Group Flag is set to 0, and the recipient endpoint retrieves a Security Context which is both valid to process the message and also associated to an OSCORE group, but the endpoint does not support the pairwise mode.
   
   - The Group Flag is set to 1, and the recipient endpoint can not retrieve a Security Context which is both valid to process the message and also associated to an OSCORE group.
    
      As per Section 6.1 of {{RFC8613}}, this holds also when retrieving a Security Context which is valid but not associated to an OSCORE group. Future specifications may define how to process incoming messages protected with a Security Contexts as in {{RFC8613}}, when the Group Flag bit is set to 1.

Otherwise, if a Security Context associated to an OSCORE group and valid to process the message is retrieved, the recipient endpoint processes the message with Group OSCORE, using the group mode (see {{mess-processing}}) if the Group Flag is set to 1, or the pairwise mode (see {{sec-pairwise-protection}}) if the Group Flag is set to 0.
   
Note that, if the Group Flag is set to 0, and the recipient endpoint retrieves a Security Context which is valid to process the message but is not associated to an OSCORE group, then the message is processed according to {{RFC8613}}.

# Message Processing in Group Mode # {#mess-processing}

When using the group mode, messages are protected and processed as specified in {{RFC8613}}, with the modifications described in this section. The security objectives of the group mode are discussed in {{ssec-sec-objectives}}. The group mode MUST be supported.

During all the steps of the message processing, an endpoint MUST use the same Security Context for the considered group. That is, an endpoint MUST NOT install a new Security Context for that group (see {{new-sec-context}}) until the message processing is completed.

The group mode MUST be used to protect group requests intended for multiple recipients or for the whole group. This includes both requests directly addressed to multiple recipients, e.g. sent by the client over multicast, as well as requests sent by the client over unicast to a proxy, that forwards them to the intended recipients over multicast {{I-D.ietf-core-groupcomm-bis}}.

As per {{RFC7252}}{{I-D.ietf-core-groupcomm-bis}}, group requests sent over multicast MUST be Non-Confirmable, and thus are not retransmitted by the CoAP messaging layer. Instead, applications should store such outgoing messages for a predefined, sufficient amount of time, in order to correctly perform possible retransmissions at the application layer. According to Section 5.2.3 of {{RFC7252}}, responses to Non-Confirmable group requests SHOULD also be Non-Confirmable, but endpoints MUST be prepared to receive Confirmable responses in reply to a Non-Confirmable group request. Confirmable group requests are acknowledged in non-multicast environments, as specified in {{RFC7252}}.

Furthermore, endpoints in the group locally perform error handling and processing of invalid messages according to the same principles adopted in {{RFC8613}}. However, a recipient MUST stop processing and silently reject any message which is malformed and does not follow the format specified in {{sec-cose-object}} of this specification, or which is not cryptographically validated in a successful way. In either case, it is RECOMMENDED that the recipient does not send back any error message. This prevents servers from replying with multiple error messages to a client sending a group request, so avoiding the risk of flooding and possibly congesting the network.


## Protecting the Request ## {#ssec-protect-request}

A client transmits a secure group request as described in Section 8.1 of {{RFC8613}}, with the following modifications.

* In step 2, the Additional Authenticated Data is modified as described in {{sec-cose-object}} of this document.

* In step 4, the encryption of the COSE object is modified as described in {{sec-cose-object}} of this document. The encoding of the compressed COSE object is modified as described in {{compression}} of this document. In particular, the Group Flag MUST be set to 1.

* In step 5, the counter signature is computed and the format of the OSCORE message is modified as described in {{sec-cose-object}} and {{compression}} of this document. In particular, the payload of the OSCORE message includes also the counter signature.

### Supporting Observe ### {#ssec-protect-request-observe}

If Observe {{RFC7641}} is supported, the following holds for each newly started observation.

* If the client intends to keep the observation active beyond a possible change of Sender ID, the client MUST store the value of the 'kid' parameter from the original Observe request, and retain it for the whole duration of the observation. Even in case the client is individually rekeyed and receives a new Sender ID from the Group Manager (see {{new-sender-id}}), the client MUST NOT update the stored value associated to a particular Observe request.

* If the client intends to keep the observation active beyond a possible change of ID Context following a group rekeying (see {{sec-group-key-management}}), then the following applies.

   - The client MUST store the value of the 'kid context' parameter from the original Observe request, and retain it for the whole duration of the observation. Upon establishing a new Security Context with a new Gid as ID Context (see {{new-sec-context}}), the client MUST NOT update the stored value associated to a particular Observe request.
   
   - The client MUST store an invariant identifier of the group, which is immutable even in case the Security Context of the group is re-established. For example, this invariant identifier can be the "group name" in {{I-D.ietf-ace-key-groupcomm-oscore}}, where it is used for joining the group and retrieving the current group keying material from the Group Manager.
   
      After a group rekeying, such an invariant information makes it simpler for the observer client to retrieve the current group keying material from the Group Manager, in case the client has missed both the rekeying messages and the first observe notification protected with the new Security Context (see {{ssec-protect-response-observe}}).

## Verifying the Request ## {#ssec-verify-request}

Upon receiving a secure group request with the Group Flag set to 1, following the procedure in {{sec-message-reception}}, a server proceeds as described in Section 8.2 of {{RFC8613}}, with the following modifications.

* In step 2, the decoding of the compressed COSE object follows {{compression}} of this document. In particular:

   - If the server discards the request due to not retrieving a Security Context associated to the OSCORE group, the server MAY respond with a 4.01 (Unauthorized) error message. When doing so, the server MAY set an Outer Max-Age option with value zero, and MAY include a descriptive string as diagnostic payload.

   - If the received 'kid context' matches an existing ID Context (Gid) but the received 'kid' does not match any Recipient ID in this Security Context, then the server MAY create a new Recipient Context for this Recipient ID and initialize it according to Section 3 of {{RFC8613}}, and also retrieve the associated public key. Such a configuration is application specific. If the application does not specify dynamic derivation of new Recipient Contexts, then the server SHALL stop processing the request.

* In step 4, the Additional Authenticated Data is modified as described in {{sec-cose-object}} of this document.

* In step 6, the server also verifies the counter signature using the public key of the client from the associated Recipient Context. In particular:

   - If the server does not have the public key of the client yet, the server MUST stop processing the request and MAY respond with a 5.03 (Service Unavailable) response. The response MAY include a Max-Age Option, indicating to the client the number of seconds after which to retry. If the Max-Age Option is not present, a retry time of 60 seconds will be assumed by the client, as default value defined in Section 5.10.5 of {{RFC7252}}.

   - If the signature verification fails, the server SHALL stop processing the request and MAY respond with a 4.00 (Bad Request) response. The server MAY set an Outer Max-Age option with value zero. The diagnostic payload MAY contain a string, which, if present, MUST be "Decryption failed" as if the decryption had failed. Furthermore, the Replay Window MUST be updated only if both the signature verification and the decryption succeed.

* Additionally, if the used Recipient Context was created upon receiving this group request and the message is not verified successfully, the server MAY delete that Recipient Context. Such a configuration, which is specified by the application, mitigates attacks that aim at overloading the server's storage.
    
A server SHOULD NOT process a request if the received Recipient ID ('kid') is equal to its own Sender ID in its own Sender Context. For an example where this is not fulfilled, see Section 7.2.1 in {{I-D.tiloca-core-observe-multicast-notifications}}.

### Supporting Observe ### {#ssec-verify-request-observe}

If Observe {{RFC7641}} is supported, the following holds for each newly started observation.

* The server MUST store the value of the 'kid' parameter from the original Observe request, and retain it for the whole duration of the observation. The server MUST NOT update the stored value of a 'kid' parameter associated to a particular Observe request, even in case the observer client is individually rekeyed and starts using a new Sender ID received from the Group Manager (see {{new-sender-id}}).

* The server MUST store the value of the 'kid context' parameter from the original Observe request, and retain it for the whole duration of the observation, beyond a possible change of ID Context following a group rekeying (see {{sec-group-key-management}}). That is, upon establishing a new Security Context with a new Gid as ID Context (see {{new-sec-context}}), the server MUST NOT update the stored value associated to the ongoing observation.

## Protecting the Response ## {#ssec-protect-response}

If a server generates a CoAP message in response to a Group OSCORE request, then the server SHALL follow the description in Section 8.3 of {{RFC8613}}, with the modifications described in this section. 

Note that the server always protects a response with the Sender Context from its latest Security Context, and that establishing a new Security Context resets the Sender Sequence Number to 0 (see {{sec-group-key-management}}).

* In step 2, the Additional Authenticated Data is modified as described in {{sec-cose-object}} of this document.

* In step 3, if the server is using a different Security Context for the response compared to what was used to verify the request (see {{sec-group-key-management}}), then the server MUST include its Sender Sequence Number as Partial IV in the response and use it to build the AEAD nonce to protect the response. This prevents the AEAD nonce from the request from being reused.

* In step 4, the encryption of the COSE object is modified as described in {{sec-cose-object}} of this document. The encoding of the compressed COSE object is modified as described in {{compression}} of this document. In particular, the Group Flag MUST be set to 1. If the server is using a different ID Context (Gid) for the response compared to what was used to verify the request (see {{sec-group-key-management}}), then the new ID Context MUST be included in the 'kid context' parameter of the response. 

* In step 5, the counter signature is computed and the format of the OSCORE message is modified as described in {{compression}} of this document. In particular, the payload of the OSCORE message includes also the counter signature.


### Supporting Observe ### {#ssec-protect-response-observe}

If Observe {{RFC7641}} is supported, the following holds when protecting notifications for an ongoing observation.

* The server MUST use the stored value of the 'kid' parameter from the original Observe request (see {{ssec-verify-request-observe}}), as value for the 'request\_kid' parameter in the external\_aad structure (see {{sec-cose-object-ext-aad}}).

* The server MUST use the stored value of the 'kid context' parameter from the original Observe request (see {{ssec-verify-request-observe}}), as value for the 'request\_kid\_context' parameter in the external\_aad structure (see {{sec-cose-object-ext-aad}}).

Furthermore, the server may have ongoing observations started by Observe requests protected with an old Security Context. After completing the establishment of a new Security Context, the server MUST protect the following notifications with the Sender Context of the new Security Context.

For each ongoing observation, the server can help the client to synchronize, by including also the 'kid context' parameter in notifications following a group rekeying, with value set to the ID Context (Gid) of the new Security Context.

If there is a known upper limit to the duration of a group rekeying, the server SHOULD include the 'kid context' parameter during that time. Otherwise, the server SHOULD include it until the Max-Age has expired for the last notification sent before the installation of the new Security Context.

## Verifying the Response ## {#ssec-verify-response}

Upon receiving a secure response message with the Group Flag set to 1, following the procedure in {{sec-message-reception}}, the client proceeds as described in Section 8.4 of {{RFC8613}}, with the following modifications.

Note that a client may receive a response protected with a Security Context different from the one used to protect the corresponding group request, and that, upon the establishment of a new Security Context, the client re-initializes its Replay Windows in its Recipient Contexts (see {{sec-group-key-management}}).

* In step 2, the decoding of the compressed COSE object is modified as described in {{compression}} of this document. In particular, a 'kid' may not be present, if the response is a reply to a request protected in pairwise mode. In such a case, the client assumes the response 'kid' to be exactly the one of the server to which the request protected in pairwise mode was intended for.

   If the response 'kid context' matches an existing ID Context (Gid) but the received/assumed 'kid' does not match any Recipient ID in this Security Context, then the client MAY create a new Recipient Context for this Recipient ID and initialize it according to Section 3 of {{RFC8613}}, and also retrieve the associated public key. If the application does not specify dynamic derivation of new Recipient Contexts, then the client SHALL stop processing the response.

* In step 3, the Additional Authenticated Data is modified as described in {{sec-cose-object}} of this document.

* In step 5, the client also verifies the counter signature using the public key of the server from the associated Recipient Context. If the verification fails, the same steps are taken as if the decryption had failed.

* Additionally, if the used Recipient Context was created upon receiving this response and the message is not verified successfully, the client MAY delete that Recipient Context. Such a configuration, which is specified by the application, mitigates attacks that aim at overloading the client's storage.


### Supporting Observe ### {#ssec-verify-response-observe}

If Observe {{RFC7641}} is supported, the following holds when verifying notifications for an ongoing observation.

* The client MUST use the stored value of the 'kid' parameter from the original Observe request (see {{ssec-protect-request-observe}}), as value for the 'request\_kid' parameter in the external\_aad structure (see {{sec-cose-object-ext-aad}}).

* The client MUST use the stored value of the 'kid context' parameter from the original Observe request (see {{ssec-protect-request-observe}}), as value for the 'request\_kid\_context' parameter in the external\_aad structure (see {{sec-cose-object-ext-aad}}).

This ensures that the client can correctly verify notifications, even in case it is individually rekeyed and starts using a new Sender ID received from the Group Manager (see {{new-sender-id}}), as well as when it installs a new Security Context with a new ID Context (Gid) following a group rekeying (see {{sec-group-key-management}}).

# Message Processing in Pairwise Mode # {#sec-pairwise-protection}

When using the pairwise mode of Group OSCORE, messages are protected and processed as in {{RFC8613}}, with the modifications described in this section. The security objectives of the pairwise mode are discussed in {{ssec-sec-objectives}}.

The pairwise mode takes advantage of an existing Security Context for the group mode to establish a Security Context shared exclusively with any other member. In order to use the pairwise mode, the signature scheme of the group mode MUST support a combined signature and encryption scheme. This can be, for example, signature using ECDSA, and encryption using AES-CCM with a key derived with ECDH.

The pairwise mode does not support the use of additional entities acting as verifiers of source authentication and integrity of group messages, such as intermediary gateways (see {{group-manager}}).

The pairwise mode MAY be supported. An endpoint implementing only a silent server does not support the pairwise mode.

If the signature algorithm used in the group supports ECDH (e.g., ECDSA, EdDSA), the pairwise mode MUST be supported by endpoints that use the CoAP Echo Option {{I-D.ietf-core-echo-request-tag}} and/or block-wise transfers {{RFC7959}}, for instance for responses after the first block-wise request, which possibly targets all servers in the group and includes the CoAP Block2 option (see Section 3.7 of {{I-D.ietf-core-groupcomm-bis}}). This prevents the attack described in {{ssec-unicast-requests}}, which leverages requests sent over unicast to a single group member and protected with the group mode.

Senders cannot use the pairwise mode to protect a message intended for multiple recipients. In fact, the pairwise mode is defined only between two endpoints and the keying material is thus only available to one recipient.

However, a sender can use the pairwise mode to protect a message sent to (but not intended for) multiple recipients, if interested in a response from only one of them. For instance, this is useful to support the address discovery service defined in {{ssec-pre-conditions}}, when a single 'kid' value is indicated in the payload of a request sent to multiple recipients, e.g. over multicast.

The Group Manager MAY indicate that the group uses also the pairwise mode, as part of the group data provided to candidate group members when joining the group.

## Pre-Conditions ## {#ssec-pre-conditions}

In order to protect an outgoing message in pairwise mode, the sender needs to know the public key and the Recipient ID for the recipient endpoint, as stored in the Recipient Context associated to that endpoint (see {{pairwise-implementation}}).

Furthermore, the sender needs to know the individual address of the recipient endpoint. This information may not be known at any given point in time. For instance, right after having joined the group, a client may know the public key and Recipient ID for a given server, but not the addressing information required to reach it with an individual, one-to-one request.

To make addressing information of individual endpoints available, servers in the group MAY expose a resource to which a client can send a group request targeting a set of servers, identified by their 'kid' values specified in the request payload. The specified set may be empty, hence identifying all the servers in the group. Further details of such an interface are out of scope for this document.

## Main Differences from OSCORE {#sec-differences-oscore-pairwise}

The pairwise mode protects messages between two members of a group, essentially following {{RFC8613}}, but with the following notable differences.

* The 'kid' and 'kid context' parameters of the COSE object are used as defined in {{sec-cose-object-kid}} of this document.

* The external_aad defined in {{sec-cose-object-ext-aad}} of this document is used for the encryption process.

* The Pairwise Sender/Recipient Keys used as Sender/Recipient keys are derived as defined in {{sec-derivation-pairwise}} of this document.

## Protecting the Request {#sec-pairwise-protection-req}

When using the pairwise mode, the request is protected as defined in Section 8.1 of {{RFC8613}}, with the differences summarized in {{sec-differences-oscore-pairwise}} of this document. The following difference also applies.

* If Observe {{RFC7641}} is supported, what defined in {{ssec-protect-request-observe}} of this document holds.

## Verifying the Request {#sec-pairwise-verify-req}

Upon receiving a request with the Group Flag set to 0, following the procedure in {{sec-message-reception}}, the server MUST process it as defined in Section 8.2 of {{RFC8613}}, with the differences summarized in {{sec-differences-oscore-pairwise}} of this document. The following differences also apply.

* If the server discards the request due to not retrieving a Security Context associated to the OSCORE group or to not supporting the pairwise mode, the server MAY respond with a 4.01 (Unauthorized) error message or a 4.02 (Bad Option) error message, respectively. When doing so, the server MAY set an Outer Max-Age option with value zero, and MAY include a descriptive string as diagnostic payload.

* If a new Recipient Context is created for this Recipient ID, new Pairwise Sender/Recipient Keys are also derived (see {{key-derivation-pairwise}}). The new Pairwise Sender/Recipient Keys are deleted if the Recipient Context is deleted as a result of the message not being successfully verified. 

* If Observe {{RFC7641}} is supported, what defined in {{ssec-verify-request-observe}} of this document holds.

## Protecting the Response {#sec-pairwise-protection-resp}

When using the pairwise mode, a response is protected as defined in Section 8.3 of {{RFC8613}}, with the differences summarized in {{sec-differences-oscore-pairwise}} of this document. The following differences also apply.

* As discussed in {{new-sender-id}}, the server can obtain a new Sender ID from the Group Manager. In such a case, the server can help the client to synchronize, by including the 'kid' parameter in a response protected in pairwise mode, even when the request was also protected in pairwise mode.

   That is, when responding to a request protected in pairwise mode, the server SHOULD include the 'kid' parameter in a response protected in pairwise mode, if it is replying to that client for the first time since the assignment of its new Sender ID.

* If Observe {{RFC7641}} is supported, what defined in {{ssec-protect-response-observe}} of this document holds.

## Verifying the Response {#sec-pairwise-verify-resp}

Upon receiving a response with the Group Flag set to 0, following the procedure in {{sec-message-reception}}, the client MUST process it as defined in Section 8.4 of {{RFC8613}}, with the differences summarized in {{sec-differences-oscore-pairwise}} of this document. The following differences also apply.

* If a new Recipient Context is created for this Recipient ID, new Pairwise Sender/Recipient Keys are also derived (see {{key-derivation-pairwise}}). The new Pairwise Sender/Recipient Keys are deleted if the Recipient Context is deleted as a result of the message not being successfully verified. 

* If Observe {{RFC7641}} is supported, what defined in {{ssec-verify-response-observe}} of this document holds.


# Security Considerations  # {#sec-security-considerations}

The same threat model discussed for OSCORE in Appendix D.1 of {{RFC8613}} holds for Group OSCORE. In addition, when using the group mode, source authentication of messages is explicitly ensured by means of counter signatures, as discussed in {{ssec-group-level-security}}.

The same considerations on supporting Proxy operations discussed for OSCORE in Appendix D.2 of {{RFC8613}} hold for Group OSCORE.

The same considerations on protected message fields for OSCORE discussed in Appendix D.3 of {{RFC8613}} hold for Group OSCORE.

The same considerations on uniqueness of (key, nonce) pairs for OSCORE discussed in Appendix D.4 of {{RFC8613}} hold for Group OSCORE. This is further discussed in {{ssec-key-nonce-uniqueness}} of this document.

The same considerations on unprotected message fields for OSCORE discussed in Appendix D.5 of {{RFC8613}} hold for Group OSCORE, with the following differences. First, the 'kid context' of request messages is part of the Additional Authenticated Data, thus safely enabling to keep observations active beyond a possible change of ID Context (Gid), following a group rekeying (see {{sec-cose-object-ext-aad}}). Second, the counter signature included in a Group OSCORE message protected in group mode is computed also over the value of the OSCORE option, which is also part of the Additional Authenticated Data used in the signing process. This is further discussed in {{ssec-cross-group-injection}} of this document.

As discussed in Section 6.2.3 of {{I-D.ietf-core-groupcomm-bis}}, Group OSCORE addresses security attacks against CoAP listed in Sections 11.2-11.6 of {{RFC7252}}, especially when run over IP multicast.

The rest of this section first discusses security aspects to be taken into account when using Group OSCORE. Then it goes through aspects covered in the security considerations of OSCORE (see Section 12 of {{RFC8613}}), and discusses how they hold when Group OSCORE is used.

## Group-level Security {#ssec-group-level-security}

The group mode described in {{mess-processing}} relies on commonly shared group keying material to protect communication within a group. This has the following implications.

* Messages are encrypted at a group level (group-level data confidentiality), i.e. they can be decrypted by any member of the group, but not by an external adversary or other external entities.

* The AEAD algorithm provides only group authentication, i.e. it ensures that a message sent to a group has been sent by a member of that group, but not necessarily by the alleged sender. This is why source authentication of messages sent to a group is ensured through a counter signature, which is computed by the sender using its own private key and then appended to the message payload.

Instead, the pairwise mode described in {{sec-pairwise-protection}} protects messages by using pairwise symmetric keys, derived from the static-static Diffie-Hellman shared secret computed from the asymmetric keys of the sender and recipient endpoint (see {{sec-derivation-pairwise}}). Therefore, in the pairwise mode, the AEAD algorithm provides both pairwise data-confidentiality and source authentication of messages, without using counter signatures.

The long-term storing of the Diffie-Hellman shared secret is a potential security issue. In fact, if the shared secret of two group members is leaked, a third group member can exploit it to impersonate any of those two group members, by deriving and using their pairwise key. The possibility of such leakage should be contemplated, as more likely to happen than the leakage of a private key, which could be rather protected at a significantly higher level than generic memory, e.g. by using a Trusted Platform Module. Therefore, there is a trade-off between the maximum amount of time a same shared secret is stored and the frequency of its re-computing.

Note that, even if an endpoint is authorized to be a group member and to take part in group communications, there is a risk that it behaves inappropriately. For instance, it can forward the content of messages in the group to unauthorized entities. However, in many use cases, the devices in the group belong to a common authority and are configured by a commissioner (see {{sec-use-cases}}), which results in a practically limited risk and enables a prompt detection/reaction in case of misbehaving.

## Uniqueness of (key, nonce) {#ssec-key-nonce-uniqueness}

The proof for uniqueness of (key, nonce) pairs in Appendix D.4 of {{RFC8613}} is also valid in group communication scenarios. That is, given an OSCORE group:

* Uniqueness of Sender IDs within the group is enforced by the Group Manager, which never reassigns the same Sender ID within the same group under the same Gid value.

* The case A in Appendix D.4 of {{RFC8613}} concerns all group requests and responses including a Partial IV (e.g. Observe notifications). In this case, same considerations from {{RFC8613}} apply here as well.

* The case B in Appendix D.4 of {{RFC8613}} concerns responses not including a Partial IV (e.g. single response to a group request). In this case, same considerations from {{RFC8613}} apply here as well.

As a consequence, each message encrypted/decrypted with the same Sender Key is processed by using a different (ID_PIV, PIV) pair. This means that nonces used by any fixed encrypting endpoint are unique. Thus, each message is processed with a different (key, nonce) pair.

## Management of Group Keying Material # {#sec-cons-group-key-management}

The approach described in this specification should take into account the risk of compromise of group members. In particular, this document specifies that a key management scheme for secure revocation and renewal of Security Contexts and group keying material should be adopted.

{{I-D.ietf-ace-key-groupcomm-oscore}} provides a simple rekeying scheme for renewing the Security Context in a group.

Alternative rekeying schemes which are more scalable with the group size may be needed in dynamic, large-scale groups where endpoints can join and leave at any time, in order to limit the impact on performance due to the Security Context and keying material update.

## Update of Security Context and Key Rotation {#ssec-key-rotation}

A group member can receive a message shortly after the group has been rekeyed, and new security parameters and keying material have been distributed by the Group Manager.

This may result in a client using an old Security Context to protect a request, and a server using a different new Security Context to protect a corresponding response. As a consequence, clients may receive a response protected with a Security Context different from the one used to protect the corresponding request.

In particular, a server may first get a request protected with the old Security Context, then install the new Security Context, and only after that produce a response to send back to the client. In such a case, as specified in {{ssec-protect-response}}, the server MUST protect the potential response using the new Security Context. Specifically, the server MUST include its Sender Sequence Number as Partial IV in the response and use it to build the AEAD nonce to protect the response. This prevents the AEAD nonce from the request from being reused with the new Security Context.

The client will process that response using the new Security Context, provided that it has installed the new security parameters and keying material before the message processing.

In case block-wise transfer {{RFC7959}} is used, the same considerations from Section 7.2 of {{I-D.ietf-ace-key-groupcomm}} hold.

Furthermore, as described below, a group rekeying may temporarily result in misaligned Security Contexts between the sender and recipient of a same message.

### Late Update on the Sender {#ssec-key-rotation-late-sender}

In this case, the sender protects a message using the old Security Context, i.e. before having installed the new Security Context. However, the recipient receives the message after having installed the new Security Context, and is thus unable to correctly process it.

A possible way to ameliorate this issue is to preserve the old, recent, Security Context for a maximum amount of time defined by the application. By doing so, the recipient can still try to process the received message using the old retained Security Context as a second attempt. This makes particular sense when the recipient is a client, that would hence be able to process incoming responses protected with the old, recent, Security Context used to protect the associated group request. Instead, a recipient server would better and more simply discard an incoming group request which is not successfully processed with the new Security Context.

This tolerance preserves the processing of secure messages throughout a long-lasting key rotation, as group rekeying processes may likely take a long time to complete, especially in large scale groups. On the other hand, a former (compromised) group member can abusively take advantage of this, and send messages protected with the old retained Security Context. Therefore, a conservative application policy should not admit the retention of old Security Contexts.

### Late Update on the Recipient {#ssec-key-rotation-late-recipient}

In this case, the sender protects a message using the new Security Context, but the recipient receives that message before having installed the new Security Context. Therefore, the recipient would not be able to correctly process the message and hence discards it.

If the recipient installs the new Security Context shortly after that and the sender endpoint retransmits the message, the former will still be able to receive and correctly process the message.

In any case, the recipient should actively ask the Group Manager for an updated Security Context according to an application-defined policy, for instance after a given number of unsuccessfully decrypted incoming messages.

## Collision of Group Identifiers {#ssec-gid-collision}

In case endpoints are deployed in multiple groups managed by different non-synchronized Group Managers, it is possible for Group Identifiers of different groups to coincide.

This does not impair the security of the AEAD algorithm. In fact, as long as the Master Secret is different for different groups and this condition holds over time, AEAD keys are different among different groups.

The entity assigning an IP multicast address may help limiting the chances to experience such collisions of Group Identifiers. In particular, it may allow the Group Managers of groups using the same IP multicast address to share their respective list of assigned Group Identifiers currently in use.

## Cross-group Message Injection {#ssec-cross-group-injection}

A same endpoint is allowed to and would likely use the same public/private key pair in multiple OSCORE groups, possibly administered by different Group Managers.

When a sender endpoint sends a message protected in pairwise mode to a recipient endpoint in an OSCORE group, a malicious group member may attempt to inject the message to a different OSCORE group also including the same endpoints (see {{ssec-cross-group-injection-attack}}).

This practically relies on altering the content of the OSCORE option, and having the same MAC in the ciphertext still correctly validating, which has a success probability depending on the size of the MAC.

As discussed in {{sssec-cross-group-injection-group-mode}}, the attack is practically infeasible if the message is protected in group mode, thanks to the counter signature also bound to the OSCORE option through the Additional Authenticated Data used in the signing process (see {{sec-cose-object-ext-aad}}).

### Attack Description {#ssec-cross-group-injection-attack}

Let us consider:

* Two OSCORE groups G1 and G2, with ID Context (Group ID) Gid1 and Gid2, respectively. Both G1 and G2 use the AEAD cipher AES-CCM-16-64-128, i.e. the MAC of the ciphertext is 8 bytes in size.

* A sender endpoint X which is member of both G1 and G2, and uses the same public/private key pair in both groups. The endpoint X has Sender ID Sid1 in G1 and Sender ID Sid2 in G2. The pairs (Sid1, Gid1) and (Sid2, Gid2) identify the same public key of X in G1 and G2, respectively.

* A recipient endpoint Y which is member of both G1 and G2, and uses the same public/private key pair in both groups. The endpoint Y has Sender ID Sid3 in G1 and Sender ID Sid4 in G2. The pairs (Sid3, Gid1) and (Sid4, Gid2) identify the same public key of Y in G1 and G2, respectively.

* A malicious endpoint Z is also member of both G1 and G2. Hence, Z is able to derive the Sender Keys used by X in G1 and G2.

When X sends a message M1 addressed to Y in G1 and protected in pairwise mode, Z can intercept M1, and attempt to forge a valid message M2 to be injected in G2, making it appear as still sent by X to Y and valid to be accepted.

More in detail, Z intercepts and stops message M1, and forges a message M2 by changing the value of the OSCORE option from M1 as follows: the 'kid context' is set to G2 (rather than G1); and the 'kid' is set to Sid2 (rather than Sid1). Then, Z injects message M2 as addressed to Y in G2. 

Upon receiving M2, there is a probability equal to 2^-64 that Y successfully verifies the same unchanged MAC by using the Pairwise Recipient Key associated to X in G2.

Note that Z does not know the pairwise keys of X and Y, since it does not know and is not able to compute their shared Diffie-Hellman secret. Therefore, Z is not able to check offline if a performed forgery is actually valid, before sending the forged message to G2.

### Attack Prevention in Group Mode {#sssec-cross-group-injection-group-mode}

When a Group OSCORE message is protected with the group mode, the counter signature is computed also over the value of the OSCORE option, which is part of the Additional Authenticated Data used in the signing process (see {{sec-cose-object-ext-aad}}).

That is, other than over the ciphertext, the countersignature is computed over: the ID Context (Gid) and the Partial IV, which are always present in group requests; as well as the Sender ID of the message originator, which is always present in group requests as well as in responses to requests protected in group mode.

Since the signing process takes as input also the ciphertext of the COSE_Encrypt0 object, the countersignature is bound not only to the intended OSCORE group, hence to the triplet (Master Secret, Master Salt, ID Context), but also to a specific Sender ID in that group and to its specific symmetric key used for AEAD encryption, hence to the quartet (Master Secret, Master Salt, ID Context, Sender ID).

This makes it practically infeasible to perform the attack described in {{ssec-cross-group-injection-attack}}, since it would require the adversary to additionally forge a valid countersignature that replaces the original one in the forged message M2.

If the countersignature did not cover the OSCORE option, the attack would still be possible against response messages protected in group mode, since the same unchanged countersignature from message M1 would be also valid in message M2.

Also, the following attack simplifications would hold, since Z is able to derive the Sender/Recipient Keys of X and Y in G1 and G2. That is, Z can also set a convenient Partial IV in the response, until the same unchanged MAC is successfully verified by using G2 as 'request_kid_context', Sid2 as 'request_kid', and the symmetric key associated to X in G2.

Since the Partial IV is 5 bytes in size, this requires 2^40 operations to test all the Partial IVs, which can be done in real-time. The probability that a single given message M1 can be used to forge a response M2 for a given request would be equal to 2^-24, since there are more MAC values (8 bytes in size) than Partial IV values (5 bytes in size).

Note that, by changing the Partial IV as discussed above, any member of G1 would also be able to forge a valid signed response message M2 to be injected in the same group G1.

## Group OSCORE for Unicast Requests {#ssec-unicast-requests}

If a request is intended to be sent over unicast as addressed to a single group member, it is NOT RECOMMENDED for the client to protect the request by using the group mode as defined in {{ssec-protect-request}}.

This does not include the case where the client sends a request over unicast to a proxy, to be forwarded to multiple intended recipients over multicast {{I-D.ietf-core-groupcomm-bis}}. In this case, the client MUST protect the request with the group mode, even though it is sent to the proxy over unicast (see {{mess-processing}}).

If the client uses the group mode with its own Sender Key to protect a unicast request to a group member, an on-path adversary can, right then or later on, redirect that request to one/many different group member(s) over unicast, or to the whole OSCORE group over multicast. By doing so, the adversary can induce the target group member(s) to perform actions intended for one group member only. Note that the adversary can be external, i.e. (s)he does not need to also be a member of the OSCORE group.

This is due to the fact that the client is not able to indicate the single intended recipient in a way which is secure and possible to process for Group OSCORE on the server side. In particular, Group OSCORE does not protect network addressing information such as the IP address of the intended recipient server. It follows that the server(s) receiving the redirected request cannot assert whether that was the original intention of the client, and would thus simply assume so.

The impact of such an attack depends especially on the REST method of the request, i.e. the Inner CoAP Code of the OSCORE request message. In particular, safe methods such as GET and FETCH would trigger (several) unintended responses from the targeted server(s), while not resulting in destructive behavior. On the other hand, non safe methods such as PUT, POST and PATCH/iPATCH would result in the target server(s) taking active actions on their resources and possible cyber-physical environment, with the risk of destructive consequences and possible implications for safety.

A client can instead use the pairwise mode as defined in {{sec-pairwise-protection-req}}, in order to protect a request sent to a single group member by using pairwise keying material (see {{sec-derivation-pairwise}}). This prevents the attack discussed above by construction, as only the intended server is able to derive the pairwise keying material used by the client to protect the request. A client supporting the pairwise mode SHOULD use it to protect requests sent to a single group member over unicast, instead of using the group mode. For an example where this is not fulfilled, see Section 7.2.1 in {{I-D.tiloca-core-observe-multicast-notifications}}.

With particular reference to block-wise transfers {{RFC7959}}, Section 3.7 of {{I-D.ietf-core-groupcomm-bis}} points out that, while an initial request including the CoAP Block2 option can be sent over multicast, any other request in a transfer has to occur over unicast, individually addressing the servers in the group.

Additional considerations are discussed in {{sec-synch-challenge-response}}, with respect to requests including a CoAP Echo Option {{I-D.ietf-core-echo-request-tag}} that has to be sent over unicast, as a challenge-response method for servers to achieve synchronization of clients' Sender Sequence Number.

## End-to-end Protection {#ssec-e2e-protection}

The same considerations from Section 12.1 of {{RFC8613}} hold for Group OSCORE.

Additionally, (D)TLS and Group OSCORE can be combined for protecting message exchanges occurring over unicast. However, it is not possible to combine (D)TLS and Group OSCORE for protecting message exchanges where messages are (also) sent over multicast.


## Master Secret {#ssec-master-secret}

Group OSCORE derives the Security Context using the same construction as OSCORE, and by using the Group Identifier of a group as the related ID Context. Hence, the same required properties of the Security Context parameters discussed in Section 3.3 of {{RFC8613}} hold for this document.

With particular reference to the OSCORE Master Secret, it has to be kept secret among the members of the respective OSCORE group and the Group Manager responsible for that group. Also, the Master Secret must have a good amount of randomness, and the Group Manager can generate it offline using a good random number generator. This includes the case where the Group Manager rekeys the group by generating and distributing a new Master Secret. Randomness requirements for security are described in {{RFC4086}}.

## Replay Protection {#ssec-replay-protection}

As in OSCORE {{RFC8613}}, also Group OSCORE relies on Sender Sequence Numbers included in the COSE message field 'Partial IV' and used to build AEAD nonces.

Note that the Partial IV of an endpoint does not necessarily grow monotonically. For instance, upon exhaustion of the endpoint Sender Sequence Number, the Partial IV also gets exhausted. As discussed in {{sec-group-re-join}}, this results either in the endpoint being individually rekeyed and getting a new Sender ID, or in the establishment of a new Security Context in the group. Therefore, uniqueness of (key, nonce) pairs (see {{ssec-key-nonce-uniqueness}}) is preserved also when a new Security Context is established.

Since one-to-many communication such as multicast usually involves unreliable transports, the simplification of the Replay Window to a size of 1 suggested in Section 7.4 of {{RFC8613}} is not viable with Group OSCORE, unless exchanges in the group rely only on unicast messages.

As discussed in {{sec-synch-seq-num}}, a Replay Window may be initialized as not valid, following the loss of mutable Security Context {{ssec-loss-mutable-context}}. In particular, {{ssec-loss-mutable-context-total}} and {{ssec-loss-mutable-context-overflow}} define measures that endpoints need to take in such a situation, before resuming to accept incoming messages from other group members.

## Message Freshness {#ssec-seccons-freshness}

As discussed in {{sec-freshness}}, a server may not be able to assert whether an incoming request is fresh, in case it does not have or has lost synchronization with the client's Sender Sequence Number.

If freshness is relevant for the application, the server may (re-)synchronize with the client's Sender Sequence Number at any time, by using the approach described in {{sec-synch-challenge-response}} and based on the CoAP Echo Option {{I-D.ietf-core-echo-request-tag}}, as a variant of the approach defined in Appendix B.1.2 of {{RFC8613}} applicable to Group OSCORE.

## Client Aliveness {#ssec-client-aliveness}

Building on Section 12.5 of {{RFC8613}}, a server may use the CoAP Echo Option {{I-D.ietf-core-echo-request-tag}} to verify the aliveness of the client that originated a received request, by using the approach described in {{sec-synch-challenge-response}} of this specification.

## Cryptographic Considerations {#ssec-crypto-considerations}

The same considerations from Section 12.6 of {{RFC8613}} about the maximum Sender Sequence Number hold for Group OSCORE. 

As discussed in {{ssec-wrap-around-partial-iv}}, an endpoint that experiences an exhaustion of its own Sender Sequence Numbers MUST NOT protect further messages including a Partial IV, until it has derived a new Sender Context. This prevents the endpoint to reuse the same AEAD nonces with the same Sender Key.

In order to renew its own Sender Context, the endpoint SHOULD inform the Group Manager, which can either renew the whole Security Context by means of group rekeying, or provide only that endpoint with a new Sender ID value. In either case, the endpoint derives a new Sender Context, and in particular a new Sender Key.

Additionally, the same considerations from Section 12.6 of {{RFC8613}} hold for Group OSCORE, about building the AEAD nonce and the secrecy of the Security Context parameters.

The EdDSA signature algorithm and the elliptic curve Ed25519 {{RFC8032}} are mandatory to implement. For endpoints that support the pairwise mode, the ECDH-SS + HKDF-256 algorithm specified in Section 6.3.1 of {{I-D.ietf-cose-rfc8152bis-algs}} and the X25519 curve {{RFC7748}} are also mandatory to implement. 

Constrained IoT devices may alternatively represent Montgomery curves and (twisted) Edwards curves {{RFC7748}} in the short-Weierstrass form Wei25519, with which the algorithms ECDSA25519 and ECDH25519 can be used for signature operations and Diffie-Hellman secret calculation, respectively {{I-D.ietf-lwig-curve-representations}}.

For many constrained IoT devices, it is problematic to support more than one signature algorithm or multiple whole cipher suites. As a consequence, some deployments using, for instance, ECDSA with NIST P-256 may not support the mandatory signature algorithm but that should not be an issue for local deployments.

The derivation of pairwise keys defined in {{key-derivation-pairwise}} is compatible with ECDSA and EdDSA asymmetric keys, but is not compatible with RSA asymmetric keys. The security of using the same key pair for Diffie-Hellman and for signing is demonstrated in {{Degabriele}}. 

## Message Segmentation {#ssec-message-segmentation}

The same considerations from Section 12.7 of {{RFC8613}} hold for Group OSCORE.

## Privacy Considerations {#ssec-privacy}

Group OSCORE ensures end-to-end integrity protection and encryption of the message payload and all options that are not used for proxy operations. In particular, options are processed according to the same class U/I/E that they have for OSCORE. Therefore, the same privacy considerations from Section 12.8 of {{RFC8613}} hold for Group OSCORE.

Furthermore, the following privacy considerations hold about the OSCORE option, which may reveal information on the communicating endpoints.

* The 'kid' parameter, which is intended to help a recipient endpoint to find the right Recipient Context, may reveal information about the Sender Endpoint. When both a request and the corresponding responses include the 'kid' parameter, this may reveal information about both a client sending a request and all the possibly replying servers sending their own individual response.

* The 'kid context' parameter, which is intended to help a recipient endpoint to find the right Security Context, reveals information about the sender endpoint. In particular, it reveals that the sender endpoint is a member of a particular OSCORE group, whose current Group ID is indicated in the 'kid context' parameter.

When receiving a group request, each of the recipient endpoints can reply with a response that includes its Sender ID as 'kid' parameter. All these responses will be matchable with the request through the Token. Thus, even if these responses do not include a 'kid context' parameter, it becomes possible to understand that the responder endpoints are in the same group of the requester endpoint.

Furthermore, using the mechanisms described in {{sec-synch-challenge-response}} to achieve Sender Sequence Number synchronization with a client may reveal when a server device goes through a reboot. This can be mitigated by the server device storing the precise state of the Replay Window of each known client on a clean shutdown.

Finally, the mechanism described in {{ssec-gid-collision}} to prevent collisions of Group Identifiers from different Group Managers may reveal information about events in the respective OSCORE groups. In particular, a Group Identifier changes when the corresponding group is rekeyed. Thus, Group Managers might use the shared list of Group Identifiers to infer the rate and patterns of group membership changes triggering a group rekeying, e.g. due to newly joined members or evicted (compromised) members. In order to alleviate this privacy concern, it should be hidden from the Group Managers which exact Group Manager has currently assigned which Group Identifiers in its OSCORE groups.

# IANA Considerations # {#iana}

Note to RFC Editor: Please replace "\[This Document\]" with the RFC number of this specification and delete this paragraph.

This document has the following actions for IANA.

## OSCORE Flag Bits Registry {#iana-cons-flag-bits}

IANA is asked to add the following value entry to the "OSCORE Flag Bits" subregistry defined in Section 13.7 of {{RFC8613}} as part of the "CoRE Parameters" registry.

~~~~~~~~~~~
+--------------+------------+-----------------------------+-----------+
| Bit Position |    Name    |         Description         | Reference |
+--------------+------------+-----------------------------+-----------+
|       2      | Group Flag | For using a Group OSCORE    | [This     |
|              |            | Security Context, set to 1  | Document] |
|              |            | if the message is protected |           |
|              |            | with the group mode         |           |
+--------------+------------+-----------------------------+-----------+
~~~~~~~~~~~

--- back

# Assumptions and Security Objectives # {#sec-requirements}

This section presents a set of assumptions and security objectives for the approach described in this document. The rest of this section refers to three types of groups:

* Application group, i.e. a set of CoAP endpoints that share a common pool of resources.

* Security group, as defined in {{terminology}} of this specification. There can be a one-to-one or a one-to-many relation between security groups and application groups, and vice versa.

* CoAP group, i.e. a set of CoAP endpoints where each endpoint is configured to receive one-to-many CoAP requests, e.g. sent to the group's associated IP multicast address and UDP port as defined in {{I-D.ietf-core-groupcomm-bis}}. An endpoint may be a member of multiple CoAP groups. There can be a one-to-one or a one-to-many relation between application groups and CoAP groups. Note that a device sending a CoAP request to a CoAP group is not necessarily itself a member of that group: it is a member only if it also has a CoAP server endpoint listening to requests for this CoAP group, sent to the associated IP multicast address and port. In order to provide secure group communication, all members of a CoAP group as well as all further endpoints configured only as clients sending CoAP (multicast) requests to the CoAP group have to be member of a security group. There can be a one-to-one or a one-to-many relation between security groups and CoAP groups, and vice versa.

## Assumptions # {#ssec-sec-assumptions}

The following points are assumed to be already addressed and are out of the scope of this document.

* Multicast communication topology: this document considers both 1-to-N (one sender and multiple recipients) and M-to-N (multiple senders and multiple recipients) communication topologies. The 1-to-N communication topology is the simplest group communication scenario that would serve the needs of a typical Low-power and Lossy Network (LLN). Examples of use cases that benefit from secure group communication are provided in {{sec-use-cases}}.

    In a 1-to-N communication model, only a single client transmits data to the CoAP group, in the form of request messages; in an M-to-N communication model (where M and N do not necessarily have the same value), M clients transmit data to the CoAP group. According to {{I-D.ietf-core-groupcomm-bis}}, any possible proxy entity is supposed to know about the clients. Also, every client expects and is able to handle multiple response messages associated to a same request sent to the CoAP group.
    
* Group size: security solutions for group communication should be able to adequately support different and possibly large security groups. The group size is the current number of members in a security group. In the use cases mentioned in this document, the number of clients (normally the controlling devices) is expected to be much smaller than the number of servers (i.e. the controlled devices). A security solution for group communication that supports 1 to 50 clients would be able to properly cover the group sizes required for most use cases that are relevant for this document. The maximum group size is expected to be in the range of 2 to 100 devices. Security groups larger than that should be divided into smaller independent groups.

* Communication with the Group Manager: an endpoint must use a secure dedicated channel when communicating with the Group Manager, also when not registered as a member of the security group.

* Provisioning and management of Security Contexts: a Security Context must be established among the members of the security group. A secure mechanism must be used to generate, revoke and (re-)distribute keying material, communication policies and security parameters in the security group. The actual provisioning and management of the Security Context is out of the scope of this document.

* Multicast data security ciphersuite: all members of a security group must agree on a ciphersuite to provide authenticity, integrity and confidentiality of messages in the group. The ciphersuite is specified as part of the Security Context.

* Backward security: a new device joining the security group should not have access to any old Security Contexts used before its joining. This ensures that a new member of the security group is not able to decrypt confidential data sent before it has joined the security group. The adopted key management scheme should ensure that the Security Context is updated to ensure backward confidentiality. The actual mechanism to update the Security Context and renew the group keying material in the security group upon a new member's joining has to be defined as part of the group key management scheme.

* Forward security: entities that leave the security group should not have access to any future Security Contexts or message exchanged within the security group after their leaving. This ensures that a former member of the security group is not able to decrypt confidential data sent within the security group anymore. Also, it ensures that a former member is not able to send protected messages to the security group anymore. The actual mechanism to update the Security Context and renew the group keying material in the security group upon a member's leaving has to be defined as part of the group key management scheme.

## Security Objectives {#ssec-sec-objectives}

The approach described in this document aims at fulfilling the following security objectives:

* Data replay protection: group request messages or response messages replayed within the security group must be detected.

* Data confidentiality: messages sent within the security group shall be encrypted.

* Group-level data confidentiality: the group mode provides group-level data confidentiality since messages are encrypted at a group level, i.e. in such a way that they can be decrypted by any member of the security group, but not by an external adversary or other external entities.

* Pairwise data confidentiality: the pairwise mode especially provides pairwise data confidentiality, since messages are encrypted using pairwise keying material shared between any two group members, hence they can be decrypted only by the intended single recipient.

* Source message authentication: messages sent within the security group shall be authenticated. That is, it is essential to ensure that a message is originated by a member of the security group in the first place, and in particular by a specific, identifiable member of the security group.

* Message integrity: messages sent within the security group shall be integrity protected. That is, it is essential to ensure that a message has not been tampered with, either by a group member, or by an external adversary or other external entities which are not members of the security group.

* Message ordering: it must be possible to determine the ordering of messages coming from a single sender. In accordance with OSCORE {{RFC8613}}, this results in providing absolute freshness of responses that are not notifications, as well as relative freshness of group requests and notification responses. It is not required to determine ordering of messages from different senders.

# List of Use Cases # {#sec-use-cases}

Group Communication for CoAP {{I-D.ietf-core-groupcomm-bis}} provides the necessary background for multicast-based CoAP communication, with particular reference to low-power and lossy networks (LLNs) and resource constrained environments. The interested reader is encouraged to first read {{I-D.ietf-core-groupcomm-bis}} to understand the non-security related details. This section discusses a number of use cases that benefit from secure group communication, and refers to the three types of groups from {{sec-requirements}}. Specific security requirements for these use cases are discussed in {{sec-requirements}}.

* Lighting control: consider a building equipped with IP-connected lighting devices, switches, and border routers. The lighting devices acting as servers are organized into application groups and CoAP groups, according to their physical location in the building. For instance, lighting devices in a room or corridor can be configured as members of a single application group and corresponding CoAP group. Those lighting devices together with the switches acting as clients in the same room or corridor can be configured as members of the corresponding security group. Switches are then used to control the lighting devices by sending on/off/dimming commands to all lighting devices in the CoAP group, while border routers connected to an IP network backbone (which is also multicast-enabled) can be used to interconnect routers in the building. Consequently, this would also enable logical groups to be formed even if devices with a role in the lighting application may be physically in different subnets (e.g. on wired and wireless networks). Connectivity between lighting devices may be realized, for instance, by means of IPv6 and (border) routers supporting 6LoWPAN {{RFC4944}}{{RFC6282}}. Group communication enables synchronous operation of a set of connected lights, ensuring that the light preset (e.g. dimming level or color) of a large set of luminaires are changed at the same perceived time. This is especially useful for providing a visual synchronicity of light effects to the user. As a practical guideline, events within a 200 ms interval are perceived as simultaneous by humans, which is necessary to ensure in many setups. Devices may reply back to the switches that issue on/off/dimming commands, in order to report about the execution of the requested operation (e.g. OK, failure, error) and their current operational status. In a typical lighting control scenario, a single switch is the only entity responsible for sending commands to a set of lighting devices. In more advanced lighting control use cases, a M-to-N communication topology would be required, for instance in case multiple sensors (presence or day-light) are responsible to trigger events to a set of lighting devices. Especially in professional lighting scenarios, the roles of client and server are configured by the lighting commissioner, and devices strictly follow those roles.

* Integrated building control: enabling Building Automation and Control Systems (BACSs) to control multiple heating, ventilation and air-conditioning units to predefined presets. Controlled units can be organized into application groups and CoAP groups in order to reflect their physical position in the building, e.g. devices in the same room can be configured as members of a single application group and corresponding CoAP group. As a practical guideline, events within intervals of seconds are typically acceptable. Controlled units are expected to possibly reply back to the BACS issuing control commands, in order to report about the execution of the requested operation (e.g. OK, failure, error) and their current operational status.

* Software and firmware updates: software and firmware updates often comprise quite a large amount of data. This can overload a Low-power and Lossy Network (LLN) that is otherwise typically used to deal with only small amounts of data, on an infrequent base. Rather than sending software and firmware updates as unicast messages to each individual device, multicasting such updated data to a larger set of devices at once displays a number of benefits. For instance, it can significantly reduce the network load and decrease the overall time latency for propagating this data to all devices. Even if the complete whole update process itself is secured, securing the individual messages is important, in case updates consist of relatively large amounts of data. In fact, checking individual received data piecemeal for tampering avoids that devices store large amounts of partially corrupted data and that they detect tampering hereof only after all data has been received. Devices receiving software and firmware updates are expected to possibly reply back, in order to provide a feedback about the execution of the update operation (e.g. OK, failure, error) and their current operational status.

* Parameter and configuration update: by means of multicast communication, it is possible to update the settings of a set of similar devices, both simultaneously and efficiently. Possible parameters are related, for instance, to network load management or network access controls. Devices receiving parameter and configuration updates are expected to possibly reply back, to provide a feedback about the execution of the update operation (e.g. OK, failure, error) and their current operational status.

* Commissioning of Low-power and Lossy Network (LLN) systems: a commissioning device is responsible for querying all devices in the local network or a selected subset of them, in order to discover their presence, and be aware of their capabilities, default configuration, and operating conditions. Queried devices displaying similarities in their capabilities and features, or sharing a common physical location can be configured as members of a single application group and corresponding CoAP group. Queried devices are expected to reply back to the commissioning device, in order to notify their presence, and provide the requested information and their current operational status.

* Emergency multicast: a particular emergency related information (e.g. natural disaster) is generated and multicast by an emergency notifier, and relayed to multiple devices. The latter may reply back to the emergency notifier, in order to provide their feedback and local information related to the ongoing emergency. This kind of setups should additionally rely on a fault tolerance multicast algorithm, such as Multicast Protocol for Low-Power and Lossy Networks (MPL).

# Example of Group Identifier Format {#gid-ex}

This section provides an example of how the Group Identifier (Gid) can be specifically formatted. That is, the Gid can be composed of two parts, namely a Group Prefix and a Group Epoch.

For each group, the Group Prefix is constant over time and is uniquely defined in the set of all the groups associated to the same Group Manager. The choice of the Group Prefix for a given group's Security Context is application specific. The size of the Group Prefix directly impact on the maximum number of distinct groups under the same Group Manager.

The Group Epoch is set to 0 upon the group's initialization, and is incremented by 1 each time new keying material, together with a new Gid, is distributed to the group in order to establish a new Security Context (see {{sec-group-key-management}}).

As an example, a 3-byte Gid can be composed of: i) a 1-byte Group Prefix '0xb1' interpreted as a raw byte string; and ii) a 2-byte Group Epoch interpreted as an unsigned integer ranging from 0 to 65535. Then, after having established the Common Context 61532 times in the group, its Gid will assume value '0xb1f05c'.

Using an immutable Group Prefix for a group assumes that enough time elapses before all possible Group Epoch values are used, since the Group Manager never reassigns the same Gid to the same group. Thus, the expected highest rate for addition/removal of group members and consequent group rekeying should be taken into account for a proper dimensioning of the Group Epoch size.

As discussed in {{ssec-gid-collision}}, if endpoints are deployed in multiple groups managed by different non-synchronized Group Managers, it is possible that Group Identifiers of different groups coincide at some point in time. In this case, a recipient has to handle coinciding Group Identifiers, and has to try using different Security Contexts to process an incoming message, until the right one is found and the message is correctly verified. Therefore, it is favorable that Group Identifiers from different Group Managers have a size that result in a small probability of collision. How small this probability should be is up to system designers.

# Set-up of New Endpoints # {#setup}

An endpoint joins a group by explicitly interacting with the responsible Group Manager. When becoming members of a group, endpoints are not required to know how many and what endpoints are in the same group.

Communications between a joining endpoint and the Group Manager rely on the CoAP protocol and must be secured. Specific details on how to secure communications between joining endpoints and a Group Manager are out of the scope of this document.

The Group Manager must verify that the joining endpoint is authorized to join the group. To this end, the Group Manager can directly authorize the joining endpoint, or expect it to provide authorization evidence previously obtained from a trusted entity. Further details about the authorization of joining endpoints are out of scope.

In case of successful authorization check, the Group Manager generates a Sender ID assigned to the joining endpoint, before proceeding with the rest of the join process. That is, the Group Manager provides the joining endpoint with the keying material and parameters to initialize the Security Context (see {{sec-context}}). The actual provisioning of keying material and parameters to the joining endpoint is out of the scope of this document.

It is RECOMMENDED that the join process adopts the approach described in {{I-D.ietf-ace-key-groupcomm-oscore}} and based on the ACE framework for Authentication and Authorization in constrained environments {{I-D.ietf-ace-oauth-authz}}. 

# Challenge-Response Synchronization # {#sec-synch-challenge-response}

This section describes a possible approach that a server endpoint can use to synchronize with Sender Sequence Numbers of client endpoints in the group. In particular, the server performs a challenge-response exchange with a client, by using the Echo Option for CoAP described in Section 2 of {{I-D.ietf-core-echo-request-tag}} and according to Appendix B.1.2 of {{RFC8613}}.

That is, upon receiving a request from a particular client for the first time, the server processes the message as described in this specification, but, even if valid, does not deliver it to the application. Instead, the server replies to the client with an OSCORE protected 4.01 (Unauthorized) response message, including only the Echo Option and no diagnostic payload. The Echo option value SHOULD NOT be reused; when it is reused, it MUST be highly unlikely to have been used with this client recently. Since this response is protected with the Security Context used in the group, the client will consider the response valid upon successfully decrypting and verifying it.

The server stores the Echo Option value included therein, together with the pair (gid,kid), where 'gid' is the Group Identifier of the OSCORE group and 'kid' is the Sender ID of the client in the group, as specified in the 'kid context' and 'kid' fields of the OSCORE Option of the request, respectively. After a group rekeying has been completed and a new Security Context has been established in the group, which results also in a new Group Identifier (see {{sec-group-key-management}}), the server MUST delete all the stored Echo values associated to members of that group.

Upon receiving a 4.01 (Unauthorized) response that includes an Echo Option and originates from a verified group member, the client sends a request as a unicast message addressed to the same server, echoing the Echo Option value. The client MUST NOT send the request including the Echo Option over multicast.

If the signature algorithm used in the group supports ECDH (e.g. ECDSA, EdDSA), the client MUST use the pairwise mode of Group OSCORE to protect the request, as described in {{sec-pairwise-protection-req}}. Note that, as defined in {{sec-pairwise-protection}}, members of such a group and that use the Echo Option MUST support the pairwise mode.

The client does not necessarily resend the same group request, but can instead send a more recent one, if the application permits it. This makes it possible for the client to not retain previously sent group requests for full retransmission, unless the application explicitly requires otherwise. In either case, the client uses a fresh Sender Sequence Number value from its own Sender Context. If the client stores group requests for possible retransmission with the Echo Option, it should not store a given request for longer than a preconfigured time interval. Note that the unicast request echoing the Echo Option is correctly treated and processed as a message, since the 'kid context' field including the Group Identifier of the OSCORE group is still present in the OSCORE Option as part of the COSE object (see {{sec-cose-object}}).

Upon receiving the unicast request including the Echo Option, the server performs the following verifications.

* If the server does not store an Echo Option value for the pair (gid,kid), it considers: i) the time t1 when it has established the Security Context used to protect the received request; and ii) the time t2 when the request has been received. Since a valid request cannot be older than the Security Context used to protect it, the server verifies that (t2 - t1) is less than the largest amount of time acceptable to consider the request fresh.

* If the server stores an Echo Option value for the pair (gid,kid) associated to that same client in the same group, the server verifies that the option value equals that same stored value previously sent to that client. 

If the verifications above fail, the server MUST NOT process the request further and MAY send a 4.01 (Unauthorized) response including an Echo Option.

If the verifications above are successful and the Replay Window has not been set yet, the server updates its Replay Window to mark the current Sender Sequence Number from the latest received request as seen (but all newer ones as new), and delivers the message as fresh to the application. Otherwise, it discards the verification result and treats the message as fresh or as a replay, according to the existing Replay Window.

A server should not deliver requests from a given client to the application until one valid request from that same client has been verified as fresh, as conveying an echoed Echo Option {{I-D.ietf-core-echo-request-tag}}. Also, a server may perform the challenge-response described above at any time, if synchronization with Sender Sequence Numbers of clients is lost, for instance after a device reboot. A client has to be always ready to perform the challenge-response based on the Echo Option in case a server starts it.

It is the role of the server application to define under what circumstances Sender Sequence Numbers lose synchronization. This can include experiencing a "large enough" gap D = (SN2 - SN1), between the Sender Sequence Number SN1 of the latest accepted group request from a client and the Sender Sequence Number SN2 of a group request just received from that client. However, a client may send several unicast requests to different group members as protected with the pairwise mode (see {{sec-pairwise-protection-req}}), which may result in the server experiencing the gap D in a relatively short time. This would induce the server to perform more challenge-response exchanges than actually needed.

To ameliorate this, the server may rather rely on a trade-off between the Sender Sequence Number gap D and a time gap T = (t2 - t1), where t1 is the time when the latest group request from a client was accepted and t2 is the time when the latest group request from that client has been received, respectively. Then, the server can start a challenge-response when experiencing a time gap T larger than a given, preconfigured threshold. Also, the server can start a challenge-response when experiencing a Sender Sequence Number gap D greater than a different threshold, computed as a monotonically increasing function of the currently experienced time gap T.

The challenge-response approach described in this appendix provides an assurance of absolute message freshness. However, it can result in an impact on performance which is undesirable or unbearable, especially in large groups where many endpoints at the same time might join as new members or lose synchronization.

Note that endpoints configured as silent servers are not able to perform the challenge-response described above, as they do not store a Sender Context to secure the 4.01 (Unauthorized) response to the client. Therefore, silent servers should adopt alternative approaches to achieve and maintain synchronization with sender sequence numbers of clients.

Since requests including the Echo Option are sent over unicast, a server can be a victim of the attack discussed in {{ssec-unicast-requests}}, when such requests are protected with the group mode of Group OSCORE, as described in {{ssec-protect-request}}.

Instead, protecting requests with the Echo Option by using the pairwise mode of Group OSCORE as described in {{sec-pairwise-protection-req}} prevents the attack in {{ssec-unicast-requests}}. In fact, only the exact server involved in the Echo exchange is able to derive the correct pairwise key used by the client to protect the request including the Echo Option.

In either case, an internal on-path adversary would not be able to mix up the Echo Option value of two different unicast requests, sent by a same client to any two different servers in the group. In fact, if the group mode was used, this would require the adversary to forge the client's countersignature in both such requests. As a consequence, each of the two servers remains able to selectively accept a request with the Echo Option only if it is waiting for that exact integrity-protected Echo Option value, and is thus the intended recipient.

# No Verification of Signatures in Group Mode # {#sec-no-source-auth}

There are some application scenarios using group communication that have particularly strict requirements. One example of this is the requirement of low message latency in non-emergency lighting applications {{I-D.somaraju-ace-multicast}}. For those applications which have tight performance constraints and relaxed security requirements, it can be inconvenient for some endpoints to verify digital signatures in order to assert source authenticity of received messages protected with the group mode. In other cases, the signature verification can be deferred or only checked for specific actions. For instance, a command to turn a bulb on where the bulb is already on does not need the signature to be checked. In such situations, the counter signature needs to be included anyway as part of a message protected with the group mode, so that an endpoint that needs to validate the signature for any reason has the ability to do so.

In this specification, it is NOT RECOMMENDED that endpoints do not verify the counter signature of received messages protected with the group mode. However, it is recognized that there may be situations where it is not always required. The consequence of not doing the signature validation in messages protected with the group mode is that security in the group is based only on the group-authenticity of the shared keying material used for encryption. That is, endpoints in the group would have evidence that the received message has been originated by a group member, although not specifically identifiable in a secure way. This can violate a number of security requirements, as the compromise of any element in the group means that the attacker has the ability to control the entire group. Even worse, the group may not be limited in scope, and hence the same keying material might be used not only for light bulbs but for locks as well. Therefore, extreme care must be taken in situations where the security requirements are relaxed, so that deployment of the system will always be done safely.

# Example Values with COSE Capabilities # {#sec-cs-params-ex}

The table below provides examples of values for Counter Signature Parameters in the Common Context (see {{ssec-common-context-cs-params}}), for different values of Counter Signature Algorithm.

~~~~~~~~~~~
+-------------------+---------------------------------------------+
| Counter Signature | Example Values for Counter                  |
| Algorithm         | Signature Parameters                        |
+-------------------+---------------------------------------------+
|  (-8)   // EdDSA  | [1], [1, 6]  // 1: OKP ; 1: OKP, 6: Ed25519 |
|  (-8)   // EdDSA  | [1], [1, 7]  // 1: OKP ; 1: OKP, 7: Ed448   |
|  (-7)   // ES256  | [2], [2, 1]  // 2: EC2 ; 2: EC2, 1: P-256   |
|  (-35)  // ES384  | [2], [2, 2]  // 2: EC2 ; 2: EC2, 2: P-384   |
|  (-36)  // ES512  | [2], [2, 3]  // 2: EC2 ; 2: EC2, 3: P-521   |
|  (-37)  // PS256  | [3], [3]     // 3: RSA ; 3: RSA             |
|  (-38)  // PS384  | [3], [3]     // 3: RSA ; 3: RSA             |
|  (-39)  // PS512  | [3], [3]     // 3: RSA ; 3: RSA             |
+-------------------+---------------------------------------------+
~~~~~~~~~~~
{: #fig-examples-counter-signature-parameters title="Examples of Counter Signature Parameters" artwork-align="center"}

The table below provides examples of values for Secret Derivation Parameters in the Common Context (see {{ssec-common-context-dh-params}}), for different values of Secret Derivation Algorithm.

~~~~~~~~~~~
+-----------------------+--------------------------------------------+
| Secret Derivation     | Example Values for Secret                  |
| Algorithm             | Derivation Parameters                      |
+-----------------------+--------------------------------------------+
|  (-27)  // ECDH-SS    | [1], [1, 4]  // 1: OKP ; 1: OKP, 4: X25519 |
|         // + HKDF-256 |                                            |
|  (-27)  // ECDH-SS    | [1], [1, 5]  // 1: OKP ; 1: OKP, 5: X448   |
|         // + HKDF-256 |                                            |
|  (-27)  // ECDH-SS    | [2], [2, 1]  // 2: EC2 ; 2: EC2, 1: P-256  |
|         // + HKDF-256 |                                            |
|  (-27)  // ECDH-SS    | [2], [2, 2]  // 2: EC2 ; 2: EC2, 2: P-384  |
|         // + HKDF-256 |                                            |
|  (-27)  // ECDH-SS    | [2], [2, 3]  // 2: EC2 ; 2: EC2, 3: P-512  |
|         // + HKDF-256 |                                            |
+-----------------------+--------------------------------------------+
~~~~~~~~~~~
{: #fig-examples-counter-dh-parameters title="Examples of Secret Derivation Parameters" artwork-align="center"}

# Parameter Extensibility for Future COSE Algorithms # {#sec-future-cose-algs}

As defined in Section 8.1 of {{I-D.ietf-cose-rfc8152bis-algs}}, future algorithms can be registered in the "COSE Algorithms" Registry {{COSE.Algorithms}} as specifying none or multiple COSE capabilities.

To enable the seamless use of such future registered algorithms, this section defines a general, agile format for parameters of the Security Context (see {{ssec-common-context-cs-params}} and {{ssec-common-context-dh-params}}) and for related elements of the external_aad structure (see {{sec-cose-object-ext-aad}}).

If any of the currently registered COSE algorithms is considered, using this general format yields the same structure defined in this document for the items above, thus ensuring retro-compatibility.

## Counter Signature Parameters ## {#sec-future-cose-algs-csp}

The definition of Counter Signature Parameters in the Common Context (see {{ssec-common-context-cs-params}}) is generalized as follows.

Counter Signature Parameters is a CBOR array CS_PARAMS including N+1 elements, whose exact structure and value depend on the value of Counter Signature Algorithm.

* The first element, i.e. CS_PARAMS\[0\], is the array of the N COSE capabilities for Counter Signature Algorithm, as specified for that algorithm in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}} (see Section 8.1 of {{I-D.ietf-cose-rfc8152bis-algs}}).

* Each following element CS_PARAMS\[i\], i.e. with index i > 0, is the array of COSE capabilities for the algorithm capability specified in CS_PARAMS\[0\]\[i-1\].

   For example, if CS_PARAMS\[0\]\[0\] specifies the key type as capability of the algorithm, then CS_PARAMS\[1\] is the array of COSE capabilities for the COSE key type associated to Counter Signature Algorithm, as specified for that key type in the "Capabilities" column of the "COSE Key Types" Registry {{COSE.Key.Types}} (see Section 8.2 of {{I-D.ietf-cose-rfc8152bis-algs}}).

## Secret Derivation Parameters ## {#sec-future-cose-algs-sdp}

The definition of Secret Derivation Parameters in the Common Context (see {{ssec-common-context-dh-params}}) is generalized as follows.

Secret Derivation Parameters is a CBOR array SD_PARAMS including N+1 elements, whose exact structure and value depend on the value of Secret Derivation Algorithm.

* The first element, i.e. SD_PARAMS\[0\], is the array of the N COSE capabilities for Secret Derivation Algorithm, as specified for that algorithm in the "Capabilities" column of the "COSE Algorithms" Registry {{COSE.Algorithms}} (see Section 8.1 of {{I-D.ietf-cose-rfc8152bis-algs}}).

* Each following element SD_PARAMS\[i\], i.e. with index i > 0, is the array of COSE capabilities for the algorithm capability specified in SD_PARAMS\[0\]\[i-1\].

   For example, if SD_PARAMS\[0\]\[0\] specifies the key type as capability of the algorithm, then SD_PARAMS\[1\] is the array of COSE capabilities for the COSE key type associated to Secret Derivation Algorithm, as specified for that key type in the "Capabilities" column of the "COSE Key Types" Registry {{COSE.Key.Types}} (see Section 8.2 of {{I-D.ietf-cose-rfc8152bis-algs}}).
   
## 'par_countersign' in the external_aad ## {#sec-future-cose-algs-aad}

The definition of the 'par_countersign' element in the 'algorithms' array of the external_aad structure (see {{sec-cose-object-ext-aad}}) is generalized as follows.

The 'par_countersign' element takes the CBOR array CS_PARAMS specified by Counter Signature Parameters in the Common Context (see {{ssec-common-context-cs-params}}), considering the format generalization in {{sec-future-cose-algs}}. In particular:

- The first element 'countersign_alg_capab' is the array of COSE capabilities for the countersignature algorithm indicated in 'alg_countersign'. This is CS_PARAMS\[0\], i.e. the first element of the CBOR array CS_PARAMS specified by Counter Signature Parameters in the Common Context.

- Each following element 'countersign_capab_i' (i = 1, ..., N) is the array of COSE capabilities for the algorithm capability specified in 'countersign_alg_capab'\[i-1\]. This algorithm capability is the element CS_PARAMS\[0\]\[i-1\] of the CBOR array CS_PARAMS specified by Counter Signature Parameters in the Common Context.

   For example, if 'countersign_alg_capab'\[i-1\] specifies the key type as capability of the algorithm, then 'countersign_capab_i' is the array of COSE capabilities for the COSE key type associated to Counter Signature Algorithm, as specified for that key type in the "Capabilities" column of the "COSE Key Types" Registry {{COSE.Key.Types}} (see Section 8.2 of {{I-D.ietf-cose-rfc8152bis-algs}}).

~~~~~~~~~~~ CDDL
external_aad = bstr .cbor aad_array

aad_array = [
   oscore_version : uint,
   algorithms : [alg_aead : int / tstr,
                 alg_countersign : int / tstr,       
                 par_countersign : [countersign_alg_capab,
                                    countersign_capab_1,
                                    countersign_capab_2,
                                    ...,
                                    countersign__capab_N]],
   request_kid : bstr,
   request_piv : bstr,
   options : bstr,
   request_kid_context : bstr,
   OSCORE_option: bstr
]

countersign_alg_capab : [c_1 : any, c_2 : any, ..., c_N : any]
~~~~~~~~~~~
{: #fig-ext-aad-general title="external_aad with general 'par_countersign'" artwork-align="center"}
   
# Document Updates # {#sec-document-updates}

RFC EDITOR: PLEASE REMOVE THIS SECTION.

## Version -10 to -11 ## {#sec-10-11}

* Loss of Recipient Contexts due to their overflow.

* Added diagram on keying material components and their relation.

* Distinction between anti-replay and freshness.

* Preservation of Sender IDs over rekeying.

* Clearer cause-effect about reset of SSN.

* The GM provides public keys of group members with associated Sender IDs.

* Removed 'par_countersign_key' from the external_aad.

* One single format for the external_aad, both for encryption and signing.

* Presence of 'kid' in responses to requests protected with the pairwise mode.

* Inclusion of 'kid_context' in notifications following a group rekeying.

* Pairwise mode presented with OSCORE as baseline.

* Revised examples with signature values.

* Decoupled growth of clients' Sender Sequence Numbers and loss of synchronization for server.

* Sender IDs not recycled in the group under the same Gid.

* Processing and description of the Group Flag bit in the OSCORE option.

* Usage of the pairwise mode for multicast requests.

* Clarifications on synchronization using the Echo option.

* General format of context parameters and external_aad elements, supporting future registered COSE algorithms (new Appendix).

* Fixes and editorial improvements.

## Version -09 to -10 ## {#sec-09-10}

* Removed 'Counter Signature Key Parameters' from the Common Context.

* New parameters in the Common Context covering the DH secret derivation.

* New counter signature header parameter from draft-ietf-cose-countersign.

* Stronger policies non non-recycling of Sender IDs and Gid.

* The Sender Sequence Number is reset when establishing a new Security Context.

* Added 'request_kid_context' in the aad_array.

* The server can respond with 5.03 if the client's public key is not available.

* The observer client stores an invariant identifier of the group.

* Relaxed storing of original 'kid' for observer clients.

* Both client and server store the 'kid_context' of the original observation request.

* The server uses a fresh PIV if protecting the response with a Security Context different from the one used to protect the request.

* Clarifications on MTI algorithms and curves.

* Removed optimized requests.

* Overall clarifications and editorial revision.

## Version -08 to -09 ## {#sec-08-09}

* Pairwise keys are discarded after group rekeying.

* Signature mode renamed to group mode.

* The parameters for countersignatures use the updated COSE registries. Newly defined IANA registries have been removed.

* Pairwise Flag bit renamed as Group Flag bit, set to 1 in group mode and set to 0 in pairwise mode.

* Dedicated section on updating the Security Context.

* By default, sender sequence numbers and replay windows are not reset upon group rekeying.

* An endpoint implementing only a silent server does not support the pairwise mode.

* Separate section on general message reception.

* Pairwise mode moved to the document body.

* Considerations on using the pairwise mode in non-multicast settings.

* Optimized requests are moved as an appendix.

* Normative support for the signature and pairwise mode.

* Revised methods for synchronization with clients' sender sequence number.

* Appendix with example values of parameters for countersignatures.

* Clarifications and editorial improvements.

## Version -07 to -08 ## {#sec-07-08}

* Clarified relation between pairwise mode and group communication (Section 1).

* Improved definition of "silent server" (Section 1.1).

* Clarified when a Recipient Context is needed (Section 2).

* Signature checkers as entities supported by the Group Manager (Section 2.3).

* Clarified that the Group Manager is under exclusive control of Gid and Sender ID values in a group, with Sender ID values under each Gid value (Section 2.3).

* Mitigation policies in case of recycled 'kid' values (Section 2.4).

* More generic exhaustion (not necessarily wrap-around) of sender sequence numbers (Sections 2.5 and 10.11).

* Pairwise key considerations, as to group rekeying and Sender Sequence Numbers (Section 3).

* Added reference to static-static Diffie-Hellman shared secret (Section 3).

* Note for implementation about the external_aad for signing (Sectino 4.3.2).

* Retransmission by the application for group requests over multicast as Non-Confirmable (Section 7).

* A server MUST use its own Partial IV in a response, if protecting it with a different context than the one used for the request (Section 7.3).

* Security considerations: encryption of pairwise mode as alternative to group-level security (Section 10.1).

* Security considerations: added approach to reduce the chance of global collisions of Gid values from different Group Managers (Section 10.5).

* Security considerations: added implications for block-wise transfers when using the signature mode for requests over unicast (Section 10.7).

* Security considerations: (multiple) supported signature algorithms (Section 10.13).

* Security considerations: added privacy considerations on the approach for reducing global collisions of Gid values (Section 10.15).

* Updates to the methods for synchronizing with clients' sequence number (Appendix E).

* Simplified text on discovery services supporting the pairwise mode (Appendix G.1).

* Editorial improvements.

## Version -06 to -07 ## {#sec-06-07}

* Updated abstract and introduction.

* Clarifications of what pertains a group rekeying.

* Derivation of pairwise keying material.

* Content re-organization for COSE Object and OSCORE header compression.

* Defined the Pairwise Flag bit for the OSCORE option.

* Supporting CoAP Observe for group requests and responses.

* Considerations on message protection across switching to new keying material.

* New optimized mode based on pairwise keying material.

* More considerations on replay protection and Security Contexts upon key renewal.

* Security considerations on Group OSCORE for unicast requests, also as affecting the usage of the Echo option.

* Clarification on different types of groups considered (application/security/CoAP).

* New pairwise mode, using pairwise keying material for both requests and responses.

## Version -05 to -06 ## {#sec-05-06}

* Group IDs mandated to be unique under the same Group Manager.

* Clarifications on parameter update upon group rekeying.

* Updated external_aad structures.

* Dynamic derivation of Recipient Contexts made optional and application specific.

* Optional 4.00 response for failed signature verification on the server.

* Removed client handling of duplicated responses to multicast requests.

* Additional considerations on public key retrieval and group rekeying.

* Added Group Manager responsibility on validating public keys.

* Updates IANA registries.

* Reference to RFC 8613.

* Editorial improvements.

## Version -04 to -05 ## {#sec-04-05}

* Added references to draft-dijk-core-groupcomm-bis.

* New parameter Counter Signature Key Parameters (Section 2).

* Clarification about Recipient Contexts (Section 2).

* Two different external_aad for encrypting and signing (Section 3.1).

* Updated response verification to handle Observe notifications (Section 6.4).

* Extended Security Considerations (Section 8).

* New "Counter Signature Key Parameters" IANA Registry (Section 9.2).

## Version -03 to -04 ## {#sec-03-04}

* Added the new "Counter Signature Parameters" in the Common Context (see Section 2).

* Added recommendation on using "deterministic ECDSA" if ECDSA is used as counter signature algorithm (see Section 2).

* Clarified possible asynchronous retrieval of keying material from the Group Manager, in order to process incoming messages (see Section 2).

* Structured Section 3 into subsections.

* Added the new 'par_countersign' to the aad_array of the external_aad (see Section 3.1).

* Clarified non reliability of 'kid' as identity indicator for a group member (see Section 2.1).

* Described possible provisioning of new Sender ID in case of Partial IV wrap-around (see Section 2.2).

* The former signature bit in the Flag Byte of the OSCORE option value is reverted to reserved (see Section 4.1). 

* Updated examples of compressed COSE object, now with the sixth less significant bit in the Flag Byte of the OSCORE option value set to 0 (see Section 4.3).

* Relaxed statements on sending error messages (see Section 6).

* Added explicit step on computing the counter signature for outgoing messages (see Sections 6.1 and 6.3).

* Handling of just created Recipient Contexts in case of unsuccessful message verification (see Sections 6.2 and 6.4).

* Handling of replied/repeated responses on the client (see Section 6.4).

* New IANA Registry "Counter Signature Parameters" (see Section 9.1).

## Version -02 to -03 ## {#sec-02-03}

* Revised structure and phrasing for improved readability and better alignment with draft-ietf-core-object-security.

* Added discussion on wrap-Around of Partial IVs (see Section 2.2).

* Separate sections for the COSE Object (Section 3) and the OSCORE Header Compression (Section 4).

* The countersignature is now appended to the encrypted payload of the OSCORE message, rather than included in the OSCORE Option (see Section 4).

* Extended scope of Section 5, now titled " Message Binding, Sequence Numbers, Freshness and Replay Protection".

* Clarifications about Non-Confirmable messages in Section 5.1 "Synchronization of Sender Sequence Numbers".

* Clarifications about error handling in Section 6 "Message Processing".

* Compacted list of responsibilities of the Group Manager in Section 7.

* Revised and extended security considerations in Section 8.

* Added IANA considerations for the OSCORE Flag Bits Registry in Section 9.

* Revised Appendix D, now giving a short high-level description of a new endpoint set-up.

## Version -01 to -02 ## {#sec-01-02}

* Terminology has been made more aligned with RFC7252 and draft-ietf-core-object-security: i) "client" and "server" replace the old "multicaster" and "listener", respectively; ii) "silent server" replaces the old "pure listener".

* Section 2 has been updated to have the Group Identifier stored in the 'ID Context' parameter defined in draft-ietf-core-object-security.

* Section 3 has been updated with the new format of the Additional Authenticated Data.

* Major rewriting of Section 4 to better highlight the differences with the message processing in draft-ietf-core-object-security.

* Added Sections 7.2 and 7.3 discussing security considerations about uniqueness of (key, nonce) and collision of group identifiers, respectively.

* Minor updates to Appendix A.1 about assumptions on multicast communication topology and group size.

* Updated Appendix C on format of group identifiers, with practical implications of possible collisions of group identifiers.

* Updated Appendix D.2, adding a pointer to draft-palombini-ace-key-groupcomm about retrieval of nodes' public keys through the Group Manager.

* Minor updates to Appendix E.3 about Challenge-Response synchronization of sequence numbers based on the Echo option from draft-ietf-core-echo-request-tag.

## Version -00 to -01 ## {#sec-00-01}

* Section 1.1 has been updated with the definition of group as "security group".

* Section 2 has been updated with:

    * Clarifications on establishment/derivation of Security Contexts.

    * A table summarizing the the additional context elements compared to OSCORE.

* Section 3 has been updated with:

    * Examples of request and response messages.

    * Use of CounterSignature0 rather than CounterSignature.

    * Additional Authenticated Data including also the signature algorithm, while not including the Group Identifier any longer.

* Added Section 6, listing the responsibilities of the Group Manager.

* Added Appendix A (former section), including assumptions and security objectives.

* Appendix B has been updated with more details on the use cases.

* Added Appendix C, providing an example of Group Identifier format.

* Appendix D has been updated to be aligned with draft-palombini-ace-key-groupcomm.

# Acknowledgments # {#acknowldegment}
{: numbered="no"}

The authors sincerely thank Christian Amsuess, Stefan Beck, Rolf Blom, Carsten Bormann, Esko Dijk, Klaus Hartke, Rikard Hoeglund, Richard Kelsey, Dave Robin, Jim Schaad, Ludwig Seitz, Peter van der Stok and Erik Thormarker for their feedback and comments.

The work on this document has been partly supported by VINNOVA and the Celtic-Next project CRITISEC; the H2020 project SIFIS-Home (Grant agreement 952652); the SSF project SEC4Factory under the grant RIT17-0032; and the EIT-Digital High Impact Initiative ACTIVE.
