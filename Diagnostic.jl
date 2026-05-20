# Diagnostic.jl - Julia helper for OMO structured diagnostics
# Emit canonical JSON to stderr for steward capture

using JSON3
using Dates
using SHA

struct Diagnostic
    version::String
    source::NamedTuple
    code::String
    severity::Symbol
    category::Symbol
    message::String
    context::NamedTuple
    repair::Union{NamedTuple, Nothing}
    audit_trail::NamedTuple
end

function emit(d::Diagnostic)
    payload = Dict(
        :version => d.version,
        :source => d.source,
        :diagnostic => Dict(
            :code => d.code,
            :severity => d.severity,
            :category => d.category,
            :message => d.message,
            :context => d.context
        ),
        :repair => d.repair,
        :audit_trail => d.audit_trail
    )
    println(stderr, JSON3.write(payload))
    flush(stderr)
    return payload
end

function to_zangbeto_payload(d::Diagnostic)
    msg_hash = bytes2hex(sha2_256(Vector{UInt8}(d.message)))
    Dict(
        :code => d.code,
        :severity => d.severity == :error ? 2 : (d.severity == :warning ? 1 : 0),
        :category => Dict(
            :type => 1,
            :logic => 2,
            :security => 4,
            :receipt => 8,
            :identity => 16,
            :rhythm => 32
        )[d.category],
        :message_hash => msg_hash,
        :agent_id => get(d.context, :agent_id, ""),
        :birth_epoch => get(d.context, :birth_timestamp, 0),
        :tier => Dict("apprentice" => 1, "adept" => 2, "master" => 3)[get(d.context, :tier, "apprentice")],
        :sabbath_active => get(d.context, :sabbath_active, false),
        :repair_id => isnothing(d.repair) ? "" : d.repair[:id],
        :repair_strategy => isnothing(d.repair) ? 2 : (d.repair[:strategy] == "auto" ? 1 : (d.repair[:strategy] == "hybrid" ? 3 : 2))
    )
end

# Usage example:
# d = Diagnostic(
#     version = "1.0",
#     source = (language = "julia", package = "myapp", file = "src/main.jl", line = 42),
#     code = "OMO-ERR-001",
#     severity = :error,
#     category = :logic,
#     message = "Balance underflow",
#     context = (agent_id = "0x...", birth_timestamp = 1716234567, tier = "apprentice", sabbath_active = false),
#     repair = nothing,
#     audit_trail = (zangbeto_verified = false, timestamp = string(now()))
# )
# emit(d)