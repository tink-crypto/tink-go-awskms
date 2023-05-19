workspace(name = "tink_go_awskms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

http_file(
    name = "google_root_pem",
    executable = 0,
    sha256 = "9c9b9685ad319b9747c3fe69b46a61c11a0efabdfa09ca6a8b0c3da421036d27",
    urls = ["https://pki.goog/roots.pem"],
)

# -------------------------------------------------------------------------
# Bazel rules for Go.
# -------------------------------------------------------------------------
# Release from 2022-12-06
#
# NOTE: This version was chosen because since 0.38 this requires
# org_golang_x_tools v0.5.0 [1], while Tink imports v0.1.12. io_bazel_rules_go
# v0.37.0 is compatible with v0.1.12 [2].
#
# [1] https://github.com/bazelbuild/rules_go/blob/cf78385a58e278b542511d246bb1cef287d528e9/go/private/repositories.bzl#L73
# [2] https://github.com/bazelbuild/rules_go/blob/2a0f48241cf5a4838b9ccfde228863d75d6c646e/go/private/repositories.bzl#L73
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "56d8c5a5c91e1af73eca71a6fab2ced959b67c86d12ba37feedb0a2dfea441a6",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.37.0/rules_go-v0.37.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.37.0/rules_go-v0.37.0.zip",
    ],
)

# -------------------------------------------------------------------------
# Bazel Gazelle.
# -------------------------------------------------------------------------
# Release from 2023-01-14
http_archive(
    name = "bazel_gazelle",
    sha256 = "ecba0f04f96b4960a5b250c8e8eeec42281035970aa8852dda73098274d14a1d",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.29.0/bazel-gazelle-v0.29.0.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
# Tink Go AWS KMS Deps.
load("//:deps.bzl", "tink_go_awskms_dependencies")

# gazelle:repository_macro deps.bzl%tink_go_awskms_dependencies
tink_go_awskms_dependencies()

# TODO(b/213404399): Remove after Gazelle issue is fixed.
go_repository(
    name = "com_google_cloud_go_compute",
    importpath = "cloud.google.com/go/compute",
    sum = "h1:rSUBvAyVwNJ5uQCKNJFMwPtTvJkfN38b6Pvb9zZoqJ8=",
    version = "v0.1.0",
)

go_register_toolchains(
    nogo = "@//:tink_nogo",
    version = "1.19.9",
)

gazelle_dependencies()
