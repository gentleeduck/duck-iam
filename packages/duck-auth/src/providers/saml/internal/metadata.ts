import { DEFAULT_SAML_CONFIG } from '../saml.constants'
import type { Saml } from '../saml.types'

/**
 * Prefers the node-saml client's own generator, which knows every encoded extension, and falls back to a
 * minimal hand-rolled document.
 */
export function buildSpMetadata(opts: { client?: Saml.Client; metadata: Saml.MetadataOptions }): string {
  if (opts.client?.generateServiceProviderMetadata) {
    return opts.client.generateServiceProviderMetadata(
      opts.metadata.decryptionCert ?? null,
      opts.metadata.signingCert ?? null,
    )
  }
  return renderFallbackMetadata(opts.metadata)
}

function renderFallbackMetadata(m: Saml.MetadataOptions): string {
  const wantAssertionsSigned = m.wantAssertionsSigned ?? DEFAULT_SAML_CONFIG.wantAssertionsSigned
  // `wantAuthnResponseSigned` is deliberately not read: SPSSODescriptor has no attribute for it, so
  // there is nothing standard to emit. It used to be read into a `${x ? '' : ''}` at the end of the
  // document, which is a no-op in both branches - true and false rendered byte-identical XML.
  const nameIdFormat = m.nameIdFormat ?? DEFAULT_SAML_CONFIG.nameIdFormat
  const sslo = m.sloUrl
    ? `\n    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${escapeXml(m.sloUrl)}"/>`
    : ''
  const keyInfo = m.signingCert
    ? `
    <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${escapeXml(m.signingCert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
    : ''
  const encInfo = m.decryptionCert
    ? `
    <md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${escapeXml(m.decryptionCert)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
    : ''
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${escapeXml(m.entityId)}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="${wantAssertionsSigned}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">${keyInfo}${encInfo}${sslo}
    <md:NameIDFormat>${escapeXml(nameIdFormat)}</md:NameIDFormat>
    <md:AssertionConsumerService isDefault="true" index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${escapeXml(m.acsUrl)}"/>
  </md:SPSSODescriptor>
${m.displayName ? `  <md:Organization><md:OrganizationName xml:lang="en">${escapeXml(m.displayName)}</md:OrganizationName><md:OrganizationDisplayName xml:lang="en">${escapeXml(m.displayName)}</md:OrganizationDisplayName><md:OrganizationURL xml:lang="en">${escapeXml(m.entityId)}</md:OrganizationURL></md:Organization>` : ''}
</md:EntityDescriptor>`
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;')
}
