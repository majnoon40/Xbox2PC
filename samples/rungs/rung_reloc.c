/*
 * rung_reloc.c — linked into every rung fixture.
 *
 * A position-independent image with no absolute addresses gets no base
 * relocation table from lld-link, even with /DYNAMICBASE, and a PE without
 * relocations can only load at its preferred base. The runtime's managed
 * address space does not contain the default PE base (0x140000000), so such
 * an image cannot be placed (docs/m12-what-broke.md, entry 13). One
 * self-referential pointer in .rdata forces a DIR64 relocation, which makes
 * the image movable; nothing reads it.
 */
__attribute__((used)) const void *const rung_relocation_anchor =
    (const void *)&rung_relocation_anchor;
