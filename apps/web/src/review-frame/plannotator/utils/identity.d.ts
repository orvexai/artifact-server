/**
 * Boundary declaration for `@plannotator/ui/utils/identity` (0.63.0,
 * utils/identity.ts:24-63). The default provider resolves the author name
 * through the package's cookie-backed config store; the review frame installs
 * its own provider so no cookie is ever read or written.
 */
export interface IdentityProvider {
  getIdentity: () => string;
  isCurrentUser: (author: string | undefined) => boolean;
  isEditable?: (() => boolean) | undefined;
}

export declare function setIdentityProvider(provider: IdentityProvider): void;
