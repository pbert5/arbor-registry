{ registry, pkgs }:
let
  signer = registry.testSigner "root" "deterministic-key";
  record =
    fields:
    registry.makeEnvelope signer (
      {
        protocolEpoch = 1;
        wireVersion = 1;
        schemaVersion = 1;
        recordVersion = 1;
        generation = 1;
        issuer = "root";
        createdAt = "2026-01-01T00:00:00Z";
      }
      // fields
    );
  conflictA = record {
    recordId = "conflict";
    schema = "endpoint";
    payload = {
      id = "a";
      address = "a.invalid";
    };
  };
  conflictB = record {
    recordId = "conflict";
    schema = "endpoint";
    payload = {
      id = "b";
      address = "b.invalid";
    };
  };
  target = record {
    recordId = "target";
    schema = "endpoint";
    payload = {
      id = "target";
      identity = "node";
      generation = 1;
    };
  };
  revocation = record {
    recordId = "revoke-node";
    schema = "revocation";
    payload = {
      identity = "node";
      generation = 1;
      status = "revoked";
    };
  };
  edge =
    id: from: to:
    record {
      recordId = id;
      schema = "relationship";
      payload = {
        relationshipId = id;
        inherit from to;
        kind = "parent";
        status = "active";
        authorityRoot = "root";
      };
    };
  cycleA = edge "cycle-a" "a" "b";
  cycleB = edge "cycle-b" "b" "a";
  relationship = edge "relationship" "root" "child";
  capability = record {
    recordId = "capability";
    schema = "capability";
    payload = {
      subject = "root";
      authorityRoot = "root";
      capabilities = [
        "observe"
        "read"
      ];
    };
  };
  records = [
    conflictA
    conflictB
    target
    revocation
    cycleA
    cycleB
    relationship
    capability
  ];
  reconcile =
    input:
    registry.reconcile {
      raw = input;
      signers.root = signer;
      authorizedIssuers = [ "root" ];
    };
  baseline = reconcile records;
  reversed = reconcile [
    capability
    relationship
    cycleB
    cycleA
    revocation
    target
    conflictB
    conflictA
  ];
  grouped = reconcile [
    cycleB
    capability
    conflictB
    revocation
    relationship
    target
    cycleA
    conflictA
  ];
in
assert registry.canonical baseline == registry.canonical reversed;
assert registry.canonical baseline == registry.canonical grouped;
assert
  (builtins.filter (item: item.quarantine.code == "conflicting-generation") baseline.quarantined)
  != [ ];
assert
  (builtins.filter (item: item.quarantine.code == "revoked-generation") baseline.quarantined) != [ ];
assert (builtins.filter (item: item.quarantine.code == "parent-cycle") baseline.quarantined) != [ ];
assert baseline.materialized.relationships == [ relationship.payload ];
assert builtins.elem capability baseline.materialized.records;
pkgs.emptyFile
