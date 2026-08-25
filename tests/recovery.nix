{ registry, pkgs }:
let
  lost = registry.identityGeneration {
    identity = "parent-a";
    generation = 1;
    authority = [
      "observe"
      "recover"
    ];
  };
  recovered = registry.identityGeneration {
    identity = "parent-a";
    generation = 2;
    predecessor = "parent-a:1";
    authority = [ "observe" ];
  };
  operator = registry.approvalRecord {
    approver = "operator-1";
    role = "operator";
    subject = "parent-a";
    issuer = "operator-authority";
    generation = 1;
    operation = "recovery";
    signature = "sig-operator";
  };
  parentApproval = registry.approvalRecord {
    approver = "parent-b";
    role = "parent";
    subject = "parent-a";
    issuer = "parent-authority";
    generation = 1;
    operation = "recovery";
    signature = "sig-parent";
  };
  peerApproval = registry.approvalRecord {
    approver = "peer-1";
    role = "peer";
    subject = "parent-a";
    issuer = "peer-authority";
    generation = 1;
    operation = "recovery";
    signature = "sig-peer";
  };
  authorization = registry.recoveryAuthorization {
    identity = "parent-a";
    lostGeneration = lost;
    newGeneration = recovered;
    operator = "operator-1";
    operatorApproval = operator;
    parentApprovals = [ parentApproval ];
    peerApprovals = [ peerApproval ];
    threshold = 1;
  };
  revoked = registry.revocation {
    identity = "parent-a";
    generation = 1;
    issuer = "parent-b";
    reason = "lost-key";
  };
  relationships = [
    {
      relationshipId = "parent-a-child";
      from = "parent-a";
      to = "child";
      kind = "parent";
      status = "active";
    }
    {
      relationshipId = "standby-child";
      from = "parent-b";
      to = "child";
      kind = "standby-parent";
      status = "standby-parent";
    }
    {
      relationshipId = "child-grandchild";
      from = "child";
      to = "grandchild";
      kind = "parent";
      status = "active";
    }
  ];
  promoted = registry.promoteStandbyParent {
    inherit relationships;
    child = "child";
    standbyParent = "parent-b";
    authorization = authorization;
  };
  suspended = registry.transitionRelationship {
    relationship = builtins.elemAt relationships 0;
    status = "suspended";
    actor = "operator-1";
    reason = "parent-recovery-in-progress";
  };
  severed = registry.transitionRelationship {
    relationship = suspended.current;
    status = "severed";
    actor = "operator-1";
    reason = "old-generation-revoked";
  };
  rebound = registry.rebindRelationship {
    relationship = builtins.elemAt relationships 0;
    from = "parent-a:2";
    actor = "operator-1";
  };
  rejected = registry.recoveryAuthorization {
    identity = "parent-a";
    lostGeneration = lost;
    newGeneration = recovered;
    operator = "operator-1";
    operatorApproval = operator;
    parentApprovals = [ parentApproval ];
    peerApprovals = [ peerApproval ];
    revocations = [ revoked ];
  };
  missingSignedMetadata = registry.recoveryAuthorization {
    identity = "parent-a";
    lostGeneration = lost;
    newGeneration = recovered;
    operator = "operator-1";
    operatorApproval = registry.approvalRecord {
      approver = "operator-1";
      role = "operator";
      subject = "parent-a";
    };
  };
  authority = registry.validateAuthorityNonAmplification {
    sourceAuthority = [
      "observe"
      "recover"
    ];
    requestedAuthority = [
      "observe"
      "admin"
    ];
  };
in
assert authorization.authorized;
assert authorization.parentApprovalSet.thresholdCompatible;
assert authorization.peerApprovalSet.approvedCount == 1;
assert !rejected.authorized;
assert !missingSignedMetadata.authorized;
assert registry.isRevoked {
  identity = "parent-a";
  generation = 1;
  revocations = [ revoked ];
};
assert registry.generationUsable {
  generation = recovered;
  revocations = [ revoked ];
};
assert promoted.authorized;
assert
  promoted.retainedParents == [
    "parent-a"
    "parent-b"
  ];
assert promoted.provenance != [ ];
assert (builtins.elemAt promoted.history 0).status == "standby-parent";
assert (builtins.elemAt promoted.history 1).status == "active";
assert (builtins.elemAt suspended.history 0).status == "suspended";
assert (builtins.elemAt severed.history 0).status == "severed";
assert rebound.current.from == "parent-a:2";
assert (builtins.elemAt rebound.history 0).provenance == [ "retained" ];
assert
  (registry.retainedDescendants {
    inherit relationships;
    revokedIdentity = "parent-a";
  }) == [
    (builtins.elemAt relationships 1)
    (builtins.elemAt relationships 2)
  ];
assert !authority.valid;
assert authority.excess == [ "admin" ];
pkgs.emptyFile
