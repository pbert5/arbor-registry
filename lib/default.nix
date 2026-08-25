{ lib }:
let
  recovery = import ./recovery.nix { inherit lib; };
  inherit (builtins)
    attrNames
    concatLists
    elem
    filter
    foldl'
    hasAttr
    head
    length
    map
    match
    stringLength
    toJSON
    typeOf
    tryEval
    isAttrs
    isList
    ;
  optional = condition: value: if condition then [ value ] else [ ];
  unique = values: foldl' (out: value: if elem value out then out else out ++ [ value ]) [ ] values;
  findFirst =
    predicate: fallback: values:
    let
      hits = filter predicate values;
    in
    if hits == [ ] then fallback else head hits;
  get =
    name: fallback: attrs:
    if isAttrs attrs && hasAttr name attrs then attrs.${name} else fallback;

  familyNames = [
    "node-identity"
    "identity-generation"
    "relationship"
    "capability"
    "machine-facts"
    "hardware-snapshot"
    "configuration-intent"
    "endpoint"
    "name"
    "service"
    "trusted-peer"
    "reachability"
    "compatibility"
    "recovery-authorization"
    "revocation"
    "receipt"
  ];
  familySchemas = lib.genAttrs familyNames (_: 1);

  unsigned = envelope: if isAttrs envelope then removeAttrs envelope [ "signature" ] else { };
  canonical = value: toJSON value;
  recordKey = record: "${record.recordId}:${toString record.recordVersion}";
  issuerOf = record: get "issuer" null record;
  isType = expected: value: typeOf value == expected;
  isString = isType "string";
  isInt = isType "int";
  isNullableString = value: value == null || isString value;

  unsafeKeys = [
    "secret"
    "password"
    "passphrase"
    "token"
    "credential"
    "privatekey"
    "private-key"
    "signingkey"
    "signing-key"
    "apikey"
    "accesstoken"
    "access-token"
    "seed"
  ];
  unsafeKey = name: elem (lib.toLower name) unsafeKeys;
  unsafeString =
    value:
    typeOf value == "string"
    && (
      lib.hasPrefix "/nix/store/" value
      || lib.hasPrefix "/run/secrets/" value
      || lib.hasPrefix "-----BEGIN" value
    );
  containsUnsafe =
    value:
    if unsafeString value then
      true
    else if isList value then
      lib.any containsUnsafe value
    else if isAttrs value then
      lib.any (name: unsafeKey name || containsUnsafe value.${name}) (attrNames value)
    else
      false;

  signerFor =
    signers: issuer: if issuer != null && signers ? ${issuer} then signers.${issuer} else null;

  makeEnvelope =
    signer: fields:
    let
      base = fields // {
        protocolEpoch = get "protocolEpoch" 1 fields;
        wireVersion = get "wireVersion" 1 fields;
        schemaVersion = get "schemaVersion" 1 fields;
        recordVersion = get "recordVersion" 1 fields;
        generation = get "generation" 0 fields;
        predecessor = get "predecessor" null fields;
        requiredFeatures = get "requiredFeatures" [ ] fields;
        optionalFeatures = get "optionalFeatures" [ ] fields;
        expiresAt = get "expiresAt" null fields;
      };
    in
    base // { signature = signer.sign (canonical (unsigned base)); };

  reason = code: detail: { inherit code detail; };

  validateEnvelope =
    {
      supportedEpoch ? 1,
      supportedWireVersions ? [ 1 ],
      supportedSchemas ? familySchemas,
      supportedFeatures ? [ ],
      signers ? { },
      authorizedIssuers ? null,
      maxBytes ? 131072,
      record,
    }:
    let
      framing = tryEval (stringLength (canonical record));
      shapeOK =
        isAttrs record
        && lib.all (name: hasAttr name record) [
          "recordId"
          "recordVersion"
          "generation"
          "schema"
          "schemaVersion"
          "payload"
        ]
        && isAttrs record.payload;
      issuer = issuerOf record;
      typedOK =
        shapeOK
        && isString record.recordId
        && isInt record.recordVersion
        && isInt record.generation
        && record.generation >= 0
        && isString record.schema
        && isInt record.schemaVersion
        && isInt (get "protocolEpoch" null record)
        && isInt (get "wireVersion" null record)
        && isList (get "requiredFeatures" [ ] record)
        && isList (get "optionalFeatures" [ ] record)
        && isNullableString (get "issuer" null record)
        && isNullableString (get "subject" null record)
        && isNullableString (get "predecessor" null record)
        && isString (get "signature" "" record);
      signer = if typedOK then signerFor signers issuer else null;
      knownFamily = typedOK && hasAttr record.schema supportedSchemas;
      schemaVersionOK = knownFamily && record.schemaVersion == supportedSchemas.${record.schema};
      epochOK = typedOK && record.protocolEpoch == supportedEpoch;
      wireOK = typedOK && elem record.wireVersion supportedWireVersions;
      required = get "requiredFeatures" [ ] record;
      featuresOK =
        isList required && lib.all (feature: isString feature && elem feature supportedFeatures) required;
      authorityOK = authorizedIssuers == null || (isString issuer && elem issuer authorizedIssuers);
      safe = !containsUnsafe (unsigned record);
      signatureOK =
        typedOK && signer != null && signer.verify (canonical (unsigned record)) record.signature;
      basic =
        framing.success
        && framing.value <= maxBytes
        && shapeOK
        && typedOK
        && knownFamily
        && schemaVersionOK
        && epochOK
        && wireOK
        && featuresOK;
      accepted = basic && authorityOK && signatureOK && safe;
      quarantineCode =
        if !framing.success || framing.value > maxBytes then
          "framing-limit"
        else if !shapeOK || !typedOK then
          "malformed-record"
        else if !knownFamily then
          "unknown-schema"
        else if !schemaVersionOK then
          "unsupported-schema-version"
        else if !epochOK then
          "unknown-epoch"
        else if !wireOK then
          "unsupported-wire-version"
        else if !featuresOK then
          "unsupported-required-feature"
        else if !authorityOK then
          "unauthorized-issuer"
        else if !safe then
          "unsafe-value"
        else if !signatureOK then
          "invalid-signature"
        else
          null;
    in
    {
      inherit record accepted;
      status = if accepted then "accepted" else "quarantined";
      quarantine = if accepted then null else reason quarantineCode "record failed envelope validation";
      canonical = if framing.success then canonical (unsigned record) else null;
    };

  validateHistory =
    records:
    let
      byId = foldl' (
        out: record: out // { "${record.recordId}" = (out.${record.recordId} or [ ]) ++ [ record ]; }
      ) { } records;
      checkOne =
        record:
        let
          peers = byId.${record.recordId};
          generations = map (x: x.generation) peers;
          maxGeneration = lib.foldl' lib.max 0 generations;
          currentPeers = filter (x: x.generation == maxGeneration) peers;
          conflict = length (unique (map canonical currentPeers)) > 1;
          predecessorRecord = findFirst (
            x: x.recordId == record.predecessor && x.generation == record.generation - 1
          ) null records;
          predecessorOK =
            (record.predecessor == null && record.generation == 1)
            || (predecessorRecord != null && predecessorRecord.generation + 1 == record.generation);
          successors = filter (x: x.predecessor == record.predecessor) records;
          fork = record.predecessor != null && length successors > 1;
          current = record.generation == maxGeneration;
        in
        if fork then
          {
            inherit record;
            accepted = false;
            quarantine = reason "forked-lineage" "a predecessor has multiple successors";
          }
        else if !predecessorOK then
          {
            inherit record;
            accepted = false;
            quarantine = reason "missing-predecessor" "predecessor is not accepted";
          }
        else if conflict then
          {
            inherit record;
            accepted = false;
            quarantine = reason "conflicting-generation" "multiple records share an id and generation";
          }
        else if !current then
          {
            inherit record;
            accepted = false;
            quarantine = reason "anti-rollback" "an equal record id has a newer generation";
          }
        else
          {
            inherit record;
            accepted = true;
            quarantine = null;
          };
    in
    map checkOne records;

  materialize =
    accepted:
    let
      byFamily = family: filter (record: record.schema == family) accepted;
      ordered = values: lib.sortOn (value: toJSON value) values;
      identities = map (record: record.payload) (byFamily "node-identity");
      relationships = map (record: record.payload) (byFamily "relationship");
      latest =
        records:
        map (
          id:
          findFirst (
            x:
            x.recordId == id
            &&
              x.generation == lib.foldl' lib.max 0 (map (y: y.generation) (filter (y: y.recordId == id) records))
          ) null records
        ) (unique (map (x: x.recordId) records));
    in
    {
      inherit identities relationships;
      records = latest accepted;
      endpoints = ordered (map (record: record.payload) (byFamily "endpoint"));
      names = ordered (
        (map (record: record.payload) (byFamily "name"))
        ++ (map (record: record.payload) (byFamily "node-identity"))
      );
      services = ordered (map (record: record.payload) (byFamily "service"));
      trustedPeers = ordered (
        (map (record: record.payload) (byFamily "trusted-peer"))
        ++ (map (record: record.payload) (
          filter (record: get "kind" null record.payload == "trusted-peer") (byFamily "relationship")
        ))
      );
      reachability = ordered (map (record: record.payload) (byFamily "reachability"));
      provenance = map (record: {
        recordId = record.recordId;
        issuer = record.issuer;
      }) accepted;
    };

  reconcile =
    {
      raw,
      supportedEpoch ? 1,
      supportedWireVersions ? [ 1 ],
      supportedSchemas ? familySchemas,
      supportedFeatures ? [ ],
      signers ? { },
      authorizedIssuers ? null,
    }:
    let
      envelopeResults = map (
        record:
        validateEnvelope {
          inherit
            supportedEpoch
            supportedWireVersions
            supportedSchemas
            supportedFeatures
            signers
            authorizedIssuers
            record
            ;
        }
      ) raw;
      envelopeAccepted = map (result: result.record) (filter (result: result.accepted) envelopeResults);
      historyResults = validateHistory envelopeAccepted;
      accepted = map (result: result.record) (filter (result: result.accepted) historyResults);
      rejectedHistory = filter (result: !result.accepted) historyResults;
      quarantined =
        (map (result: result.record // { quarantine = result.quarantine; }) (
          filter (result: !result.accepted) envelopeResults
        ))
        ++ (map (result: result.record // { quarantine = result.quarantine; }) rejectedHistory);
      graph = validateGraph { relationships = relationshipRecords accepted; };
      cycleRecords = filter (
        record:
        record.schema == "relationship"
        && elem record.payload.from graph.cycles
        && elem record.payload.to graph.cycles
      ) accepted;
      cycleRecordIds = map (record: record.recordId) cycleRecords;
      graphAccepted = filter (record: !elem record.recordId cycleRecordIds) accepted;
      cycleQuarantined = map (
        record:
        record
        // {
          quarantine = reason "parent-cycle" "relationship participates in a parent cycle";
        }
      ) cycleRecords;
    in
    {
      raw = raw;
      accepted = graphAccepted;
      quarantined = quarantined ++ cycleQuarantined;
      inherit graph;
      materialized = materialize graphAccepted;
    };

  relationshipRecords =
    records: map (record: record.payload) (filter (record: record.schema == "relationship") records);
  edgeActive = edge: get "status" "active" edge == "active";
  edgeKind = edge: get "kind" null edge;
  edgesBetween =
    {
      relationships,
      from ? null,
      to ? null,
    }:
    filter (edge: (from == null || edge.from == from) && (to == null || edge.to == to)) relationships;
  parentEdges =
    relationships: filter (edge: edgeActive edge && edgeKind edge == "parent") relationships;
  parentGraph =
    relationships:
    foldl' (out: edge: out // { "${edge.from}" = (out.${edge.from} or [ ]) ++ [ edge.to ]; }) { } (
      parentEdges relationships
    );
  reachable =
    graph: starts:
    let
      go =
        seen: queue:
        if queue == [ ] then
          seen
        else
          let
            node = head queue;
            next = get node [ ] graph;
            fresh = filter (x: !elem x seen) next;
          in
          go (unique (seen ++ [ node ])) ((builtins.tail queue) ++ fresh);
    in
    builtins.tail (go [ ] starts);
  hasParentCycle =
    relationships:
    let
      graph = parentGraph relationships;
      nodes = unique (
        concatLists (
          map (edge: [
            edge.from
            edge.to
          ]) (parentEdges relationships)
        )
      );
      visit =
        node: path:
        if elem node path then
          [ node ]
        else
          concatLists (map (neighbor: visit neighbor (path ++ [ node ])) (get node [ ] graph));
    in
    unique (concatLists (map (node: visit node [ ]) nodes));
  graphQuery =
    {
      relationships,
      from,
      selector,
    }:
    let
      graph = parentGraph relationships;
      parent = reachable graph [ from ];
      reverse = foldl' (
        out: edge: out // { "${edge.to}" = (out.${edge.to} or [ ]) ++ [ edge.from ]; }
      ) { } (parentEdges relationships);
      peer = unique (
        concatLists (
          map (
            edge:
            optional (edgeActive edge && edgeKind edge == "peer" && (edge.from == from || edge.to == from)) (
              if edge.from == from then edge.to else edge.from
            )
          ) relationships
        )
      );
    in
    if selector == "local" then
      [ from ]
    else if selector == "children" then
      get from [ ] graph
    else if selector == "descendants" then
      parent
    else if selector == "parents" then
      get from [ ] reverse
    else if selector == "ancestors" then
      reachable reverse [ from ]
    else if selector == "peers" then
      peer
    else if selector == "accessible" then
      unique ([ from ] ++ parent ++ peer)
    else
      throw "unknown graph selector";

  validateGraph =
    { relationships }:
    let
      cycles = hasParentCycle relationships;
      incoming = foldl' (
        out: edge: out // { "${edge.to}" = (out.${edge.to} or [ ]) ++ [ edge.from ]; }
      ) { } (parentEdges relationships);
      multipleParents = filter (node: length (get node [ ] incoming) > 1) (attrNames incoming);
    in
    {
      inherit cycles multipleParents;
      valid = cycles == [ ];
    };

  validateCapabilities =
    { relationships, grants }:
    let
      activeParents = parentEdges relationships;
      parentOf = node: map (edge: edge.from) (filter (edge: edge.to == node) activeParents);
      rootOf = grant: get "authorityRoot" (get "issuer" null grant) grant;
      capabilitiesOf = grant: get "capabilities" [ ] grant;
      violations = filter (
        grant:
        let
          inherited = unique (
            concatLists (
              map capabilitiesOf (
                filter (other: elem other.subject (parentOf grant.subject) && rootOf other == rootOf grant) grants
              )
            )
          );
        in
        !(lib.all (capability: elem capability inherited) (capabilitiesOf grant))
      ) grants;
    in
    {
      inherit violations;
      valid = violations == [ ];
    };

  makeTransport =
    records:
    let
      ordered = lib.sortOn (
        record: "${record.createdAt}:${record.recordId}:${toString record.recordVersion}"
      ) records;
    in
    {
      append =
        record:
        makeTransport (ordered ++ optional (!(elem (recordKey record) (map recordKey ordered))) record);
      fetch = ordered;
      fetchRecords =
        {
          since ? null,
          limit ? null,
        }:
        let
          newer = if since == null then ordered else filter (record: recordKey record > since) ordered;
        in
        if limit == null then newer else builtins.take limit newer;
      snapshot = ordered;
    };

  makeDummyProvider =
    records:
    let
      transport = makeTransport records;
    in
    {
      append =
        record:
        makeDummyProvider (
          transport.fetch ++ optional (!(elem (recordKey record) (map recordKey transport.fetch))) record
        );
      fetch = args: transport.fetchRecords args;
      snapshot = transport.snapshot;
    };
in
{
  inherit
    familyNames
    familySchemas
    canonical
    unsigned
    makeEnvelope
    validateEnvelope
    reconcile
    materialize
    makeTransport
    makeDummyProvider
    relationshipRecords
    graphQuery
    validateGraph
    validateCapabilities
    parentGraph
    hasParentCycle
    ;
  testSigner = issuer: token: {
    inherit issuer;
    sign = bytes: "${token}:${bytes}";
    verify = bytes: signature: signature == "${token}:${bytes}";
  };
  inherit (recovery)
    approvalSet
    approvalRecord
    identityGeneration
    revocation
    isRevoked
    generationUsable
    recoveryAuthorization
    relationshipEvent
    rebindRelationship
    transitionRelationship
    promoteStandbyParent
    validateAuthorityNonAmplification
    retainedDescendants
    ;
}
