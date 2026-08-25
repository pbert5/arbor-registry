{ registry, pkgs }:
let
  signer = registry.testSigner "root" "fixture-key";
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
  peer = record {
    recordId = "peer-a-b";
    subject = "peer-a-b";
    schema = "peer-relationship";
    payload = {
      relationshipId = "peer-a-b";
      from = "a";
      to = "b";
      status = "active";
      scope = [ "observe" ];
      autonomy = "independent";
      cohort = "workers";
    };
  };
  peerBC = record {
    recordId = "peer-b-c";
    subject = "peer-b-c";
    schema = "peer-relationship";
    payload = {
      relationshipId = "peer-b-c";
      from = "b";
      to = "c";
      status = "active";
      scope = [ "deploy" ];
      autonomy = "independent";
    };
  };
  parent = record {
    recordId = "parent-a-d";
    subject = "parent-a-d";
    schema = "relationship";
    payload = {
      relationshipId = "parent-a-d";
      from = "a";
      to = "d";
      kind = "parent";
      status = "active";
      scope = [ "observe" ];
      autonomy = "dependent";
    };
  };
  checked = registry.reconcile {
    raw = [
      peer
      peerBC
      parent
    ];
    signers.root = signer;
  };
  relationships = registry.relationshipRecords checked.accepted;
  graph = registry.validateGraph { inherit relationships; };
in
assert checked.quarantined == [ ];
assert
  checked.materialized.peerRelationships == [
    peer.payload
    peerBC.payload
  ];
assert builtins.any (entry: entry.schema == "peer-relationship") checked.materialized.provenance;
assert
  registry.graphQuery {
    inherit relationships;
    from = "a";
    selector = "peers";
  } == [ "b" ];
assert
  registry.graphQuery {
    inherit relationships;
    from = "a";
    selector = "cohort";
  } == [
    "a"
    "b"
    "c"
  ];
assert
  registry.graphQuery {
    inherit relationships;
    from = "a";
    selector = "peer-cohort";
    scope = "deploy";
  } == [ "a" ];
assert
  registry.graphQuery {
    inherit relationships;
    from = "a";
    selector = "accessible";
  } == [
    "a"
    "d"
    "b"
  ];
assert graph.cycles == [ ];
assert
  graph.peerCohorts == [
    [
      "a"
      "b"
      "c"
    ]
  ];
assert
  (registry.reconcile {
    raw = [
      peer
      (peerBC // { signature = "tampered"; })
    ];
    signers.root = signer;
  }).quarantined != [ ];
pkgs.emptyFile
