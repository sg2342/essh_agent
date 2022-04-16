%%%    SSH Agent Protocol
%%%  draft-miller-ssh-agent-04
%%%
%%%  5.1.  Message numbers
%%%
%%%  The following numbers are used for requests from the client to the
%%%  agent.
-define(SSH_AGENTC_REQUEST_IDENTITIES, 11).
-define(SSH_AGENTC_SIGN_REQUEST, 13).
-define(SSH_AGENTC_ADD_IDENTITY, 17).
-define(SSH_AGENTC_REMOVE_IDENTITY, 18).
-define(SSH_AGENTC_REMOVE_ALL_IDENTITIES, 19).
-define(SSH_AGENTC_ADD_ID_CONSTRAINED, 25).
-define(SSH_AGENTC_ADD_SMARTCARD_KEY, 20).
-define(SSH_AGENTC_REMOVE_SMARTCARD_KEY, 21).
-define(SSH_AGENTC_LOCK, 22).
-define(SSH_AGENTC_UNLOCK, 23).
-define(SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED, 26).
-define(SSH_AGENTC_EXTENSION, 27).
%%%
%%%  The following numbers are used for replies from the agent to the
%%%  client.
%%%
-define(SSH_AGENT_FAILURE, 5).
-define(SSH_AGENT_SUCCESS, 6).
-define(SSH_AGENT_EXTENSION_FAILURE, 28).
-define(SSH_AGENT_IDENTITIES_ANSWER, 12).
-define(SSH_AGENT_SIGN_RESPONSE, 14).

%%%
%%%  5.3.  Signature flags
%%%
%%%  The following numbers may be present in signature request:
%%%  (SSH_AGENTC_SIGN_REQUEST) messages.  These flags form a bit field by
%%%  taking the logical OR of zero or more flags.
%%%
-define(SSH_AGENT_RSA_SHA2_256, 2).
-define(SSH_AGENT_RSA_SHA2_512, 4).

%%%  The flag value 1 is reserved for historical implementations.


%%%  5.2.  Constraint identifiers
%%%  The following numbers are used to identify key constraints.  These
%%%  are only used in key constraints and are not sent as message numbers.

-define(SSH_AGENT_CONSTRAIN_LIFETIME, 1).
-define(SSH_AGENT_CONSTRAIN_CONFIRM, 2).
-define(SSH_AGENT_CONSTRAIN_EXTENSION, 255).
