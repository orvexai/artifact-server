import type {HTMLAttributes} from "react";

declare module "react" {
  namespace JSX {
    interface IntrinsicElements {
      "houston-loader": HTMLAttributes<HTMLElement> & {
        readonly label?: string | undefined;
        readonly value?: number | string | undefined;
        readonly variant?: "arrival" | "comet" | "orbit" | undefined;
      };
    }
  }
}
