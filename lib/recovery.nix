{ lib }:
let
  inherit (builtins)
    elem
    filter
    length
    map
    ;
  get =
    name: fallback: value:
    if value ? ${name} then value.${name} else fallback;
  approvalsFor = role: approvals: filter (approval: get "role" "peer" approval == role) approvals;
  approved = approval: get "decision" "approve" approval == "approve";
  validApprovals = approvals: lib.all (approval: approved approval) approvals;
  count = approvals: length (filter approved approvals);
  thresholdMet =
    threshold: approvals:
    if threshold == null then count approvals > 0 else threshold > 0 && count approvals >= threshold;

  approvalSet =
    {
      purpose ? "recovery",
      approvals ? [ ],
      threshold ? null,
    }:
    {
      inherit purpose approvals threshold;
      thresholdCompatible = true;
      approvedCount = count approvals;
    };

  approvalRecord =
    {
      approver,
      role ? "peer",
      subject,
      issuer ? null,
      generation ? null,
      operation ? null,
      approverGeneration ? null,
      decision ? "approve",
      reason ? null,
      signature ? null,
    }:
    {
      type = "approval";
      inherit
        approver
        role
        subject
        issuer
        generation
        operation
        approverGeneration
        decision
        reason
        signature
        ;
      # Cryptographic verification belongs to the injected runtime verifier.
      signatureStatus = "requires-external-verifier";
    };

  identityGeneration =
    {
      identity,
      generation,
      predecessor ? null,
      status ? "active",
      authority ? [ ],
      provenance ? [ ],
    }:
    {
      type = "identity-generation";
      inherit
        identity
        generation
        predecessor
        status
        authority
        provenance
        ;
    };

  revocation =
    {
      identity,
      generation,
      issuer,
      reason,
      approvals ? [ ],
      predecessor ? null,
    }:
    {
      type = "revocation";
      inherit
        identity
        generation
        issuer
        reason
        approvals
        predecessor
        ;
    };

  isRevoked =
    {
      identity,
      generation,
      revocations ? [ ],
    }:
    lib.any (
      item:
      item.identity == identity
      && item.generation == generation
      && get "status" "revoked" item == "revoked"
    ) revocations;

  generationUsable =
    {
      generation,
      revocations ? [ ],
    }:
    !isRevoked {
      identity = generation.identity;
      inherit (generation) generation;
      inherit revocations;
    }
    && get "status" "active" generation == "active";

  recoveryAuthorization =
    {
      identity,
      lostGeneration,
      newGeneration,
      operator,
      operatorApproval ? null,
      parentApprovals ? [ ],
      peerApprovals ? [ ],
      trustedApprovers ? [ ],
      signatureVerifier ? null,
      threshold ? null,
      reason ? "recovery",
      provenance ? [ ],
      revocations ? [ ],
    }:
    let
      allApprovals =
        (if operatorApproval == null then [ ] else [ operatorApproval ])
        ++ parentApprovals
        ++ peerApprovals;
      operatorApprovals = filter (approval: get "role" null approval == "operator") allApprovals;
      parentApprovalSet = approvalSet {
        purpose = "parent-recovery";
        approvals = parentApprovals;
        inherit threshold;
      };
      peerApprovalSet = approvalSet {
        purpose = "peer-recovery";
        approvals = peerApprovals;
        inherit threshold;
      };
      signedApprovalMetadataOK =
        approval:
        let
          issuer = get "issuer" null approval;
          signature = get "signature" null approval;
          operation = get "operation" null approval;
          generation = get "generation" null approval;
        in
        builtins.isString issuer
        && issuer != ""
        && builtins.isString signature
        && signature != ""
        && operation == "recovery"
        && generation == lostGeneration.generation;
      trustedApproverOK =
        approval:
        let
          approver = get "approver" null approval;
          role = get "role" null approval;
          approverGeneration = get "approverGeneration" null approval;
        in
        builtins.isString approver
        && approver != ""
        && builtins.isString role
        && builtins.isInt approverGeneration
        && approverGeneration > 0
        && lib.any (
          trusted:
          let
            trustedIdentity = get "identity" (get "approver" null trusted) trusted;
          in
          trustedIdentity == approver
          && get "role" null trusted == role
          && get "generation" null trusted == approverGeneration
        ) trustedApprovers;
      signatureVerified =
        builtins.isFunction signatureVerifier
        && lib.all (approval: signatureVerifier approval) allApprovals;
      subjectOK = lib.all (approval: get "subject" null approval == identity) allApprovals;
      roleOK =
        (operatorApproval != null && get "approver" null operatorApproval == operator)
        && get "role" null operatorApproval == "operator"
        && lib.all (approval: get "role" null approval == "parent") parentApprovals
        && lib.all (approval: get "role" null approval == "peer") peerApprovals;
      generationOK =
        newGeneration.identity == identity
        && newGeneration.generation == lostGeneration.generation + 1
        && newGeneration.predecessor == "${identity}:${toString lostGeneration.generation}";
      authorized =
        generationOK
        && !isRevoked {
          identity = identity;
          generation = lostGeneration.generation;
          inherit revocations;
        }
        && !isRevoked {
          identity = identity;
          generation = newGeneration.generation;
          inherit revocations;
        }
        && get "status" "active" lostGeneration == "active"
        && get "status" "active" newGeneration == "active"
        && length operatorApprovals > 0
        && validApprovals operatorApprovals
        && lib.all signedApprovalMetadataOK allApprovals
        && lib.all trustedApproverOK allApprovals
        && signatureVerified
        && subjectOK
        && roleOK
        && validApprovals allApprovals
        && (parentApprovals == [ ] || thresholdMet threshold parentApprovals)
        && (peerApprovals == [ ] || thresholdMet threshold peerApprovals);
    in
    {
      type = "recovery-authorization";
      inherit
        identity
        lostGeneration
        newGeneration
        operator
        operatorApproval
        parentApprovals
        peerApprovals
        trustedApprovers
        signatureVerifier
        threshold
        reason
        provenance
        revocations
        parentApprovalSet
        peerApprovalSet
        ;
      inherit authorized;
      rejection = if authorized then null else "recovery-approval-or-lineage-failed";
    };

  relationshipEvent =
    {
      relationship,
      status,
      actor,
      reason,
      provenance ? [ ],
    }:
    {
      inherit
        relationship
        status
        actor
        reason
        provenance
        ;
    };

  rebindRelationship =
    {
      relationship,
      from ? relationship.from,
      to ? relationship.to,
      actor,
      reason ? "relationship-rebound",
    }:
    let
      rebound = relationship // {
        inherit from to;
        status = "active";
        predecessor = get "relationshipId" null relationship;
      };
    in
    {
      previous = relationship;
      current = rebound;
      history = [
        (relationshipEvent {
          inherit relationship actor reason;
          status = get "status" "active" relationship;
          provenance = [ "retained" ];
        })
        (relationshipEvent {
          relationship = rebound;
          inherit actor reason;
          status = "active";
          provenance = [ "rebound" ];
        })
      ];
      provenance = [
        {
          relationshipId = get "relationshipId" null relationship;
          inherit
            from
            to
            actor
            reason
            ;
          transition = "rebind";
        }
      ];
    };

  transitionRelationship =
    {
      relationship,
      status,
      actor,
      reason,
    }:
    let
      event = relationshipEvent {
        inherit
          relationship
          status
          actor
          reason
          ;
      };
    in
    {
      previous = relationship;
      current = relationship // {
        inherit status;
      };
      history = [ event ];
      provenance = [ event ];
    };

  promoteStandbyParent =
    {
      relationships,
      child,
      standbyParent,
      authorization,
    }:
    let
      candidate = lib.findFirst (
        edge: edge.from == standbyParent && edge.to == child && edge.kind == "standby-parent"
      ) null relationships;
      eligible = authorization.authorized && candidate != null;
      promoted =
        if eligible then
          candidate
          // {
            kind = "parent";
            status = "active";
          }
        else
          null;
      updated =
        if eligible then
          (map (edge: if edge == candidate then promoted else edge) relationships)
        else
          relationships;
    in
    {
      relationships = updated;
      promoted = promoted;
      authorized = eligible;
      retainedParents = map (edge: edge.from) (
        filter (edge: edge.to == child && edge.kind == "parent" && edge.status == "active") updated
      );
      provenance =
        if eligible then
          [
            {
              relationshipId = candidate.relationshipId;
              from = standbyParent;
              inherit child;
              transition = "standby-promotion";
              authorization = authorization.identity;
            }
          ]
        else
          [ ];
      history =
        if eligible then
          [
            (relationshipEvent {
              relationship = candidate;
              status = "standby-parent";
              actor = authorization.operator;
              reason = "standby-parent-retained-provenance";
            })
            (relationshipEvent {
              relationship = promoted;
              status = "active";
              actor = authorization.operator;
              reason = "standby-parent-promoted";
            })
          ]
        else
          [ ];
    };

  validateAuthorityNonAmplification =
    {
      sourceAuthority,
      requestedAuthority,
    }:
    {
      inherit sourceAuthority requestedAuthority;
      excess = filter (capability: !elem capability sourceAuthority) requestedAuthority;
      valid = lib.all (capability: elem capability sourceAuthority) requestedAuthority;
    };

  retainedDescendants =
    {
      relationships,
      revokedIdentity,
    }:
    filter (edge: edge.from != revokedIdentity) relationships;
in
{
  inherit
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
