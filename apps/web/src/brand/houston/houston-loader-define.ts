import "./motion/houston-loader.js";

type AttributeValue = bigint | boolean | number | string | symbol | null | undefined;

type ObservedAttributeElementConstructor = {
  readonly observedAttributes: readonly string[];
  readonly prototype: object;
};

function isObservedAttributeElementConstructor(
  constructor: CustomElementConstructor,
): constructor is CustomElementConstructor & ObservedAttributeElementConstructor {
  return "observedAttributes" in constructor && Array.isArray(constructor.observedAttributes);
}

/** Add property setters for observed attributes whose prototype only exposes a getter. */
export function addObservedAttributePropertySetters(
  elementConstructor: ObservedAttributeElementConstructor,
): void {
  for (const name of elementConstructor.observedAttributes) {
    const descriptor = Object.getOwnPropertyDescriptor(elementConstructor.prototype, name);
    if (descriptor?.get === undefined || descriptor.set !== undefined) continue;
    Object.defineProperty(elementConstructor.prototype, name, {
      ...descriptor,
      set(this: {removeAttribute(name: string): void; setAttribute(name: string, value: string): void}, value: AttributeValue) {
        if (value === null || value === undefined || value === false) {
          this.removeAttribute(name);
        } else {
          this.setAttribute(name, String(value));
        }
      },
    });
  }
}

if ("customElements" in globalThis) {
  const constructor = globalThis.customElements.get("houston-loader");
  if (constructor !== undefined && isObservedAttributeElementConstructor(constructor)) {
    addObservedAttributePropertySetters(constructor);
  }
}
