fn main() {
    embed_resource::compile("sloosh-approval.rc", embed_resource::NONE)
        .manifest_required()
        .expect("compile required Windows approval-helper manifest");
}
