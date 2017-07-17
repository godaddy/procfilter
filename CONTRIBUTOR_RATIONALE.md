
# CLA Rationale

### Caution

This document is provided as a good-faith explanation to those hesitant to enter into a CLA. It is an unofficial, non-legal, and very likely incomplete description of the developer's (not lawyer's) understanding of the rationale for having a CLA. For official interpretations and implications consult a lawyer.

### Why have a CLA?

The primary reasons to use a CLA are for explicit clarification of ownership, copyright, and patent of contributions sent back to the project. This is to protect both project owners and project users.

The liberal MIT license does not explicitly address patent or licensing of contributions sent back to the original project. This is in contrast to, for example, a GPL project where the license forces derived code to stay under the GPL or the Apache 2.0 license which has a specific clause (#5) to address contributions.

Prior to using any open-source project the legal implications of doing so should be evaluated. This would typically include examination of the project's license and CLA by a qualified lawyer. The license is the assertion of the project's usability and the CLA is the agreement to the license by the project's contributors.

Projects without a CLA rely on an implicit license or implicit acceptance of CONTRIBUTOR.txt or equivalent when someone submits a PR. This may indeed be valid and many projects do this. However, a worst case scenario could involve an adversarial contributor claiming certain licensing or patent restrictions on their contributions. This could potentially shut the project down until the dispute is resolved and puts those using those contributions (project users) at legal risk.

Having a CLA provides the strongest safeguard against this type of scenario.

### A ProcFilter-specific alternative

The MIT license was selected based on its permissiveness and we highly encourage its use. However, if the MIT license and/or CLA are unsuitable to you, consider developing a ProcFilter plugin under a separate project that's under a different license of your choosing. ProcFilter was specifically designed with an API to allow this type of flexibility.
 
