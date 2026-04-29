import { type ReactNode } from "react";
import { motion, useReducedMotion, type HTMLMotionProps, type Variants } from "framer-motion";

import { cn } from "@/lib/utils";

const pageVariants: Variants = {
  hidden: { opacity: 0, y: 10 },
  visible: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -6 },
};

const panelVariants: Variants = {
  hidden: { opacity: 0, y: 10 },
  visible: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: 6 },
};

const listVariants: Variants = {
  hidden: {},
  visible: {
    transition: {
      staggerChildren: 0.055,
      delayChildren: 0.04,
    },
  },
};

const itemVariants: Variants = {
  hidden: { opacity: 0, y: 8 },
  visible: { opacity: 1, y: 0 },
};

type MotionProps = HTMLMotionProps<"div"> & {
  children: ReactNode;
};

export function MotionPage({ children, className, ...props }: MotionProps) {
  const reducedMotion = useReducedMotion();

  return (
    <motion.div
      initial={reducedMotion ? false : "hidden"}
      animate="visible"
      exit={reducedMotion ? undefined : "exit"}
      variants={reducedMotion ? undefined : pageVariants}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function MotionPanel({ children, className, ...props }: MotionProps) {
  const reducedMotion = useReducedMotion();
  const canObserveViewport = typeof window !== "undefined" && "IntersectionObserver" in window;

  return (
    <motion.div
      initial={reducedMotion ? false : "hidden"}
      animate={reducedMotion || !canObserveViewport ? "visible" : undefined}
      whileInView={!reducedMotion && canObserveViewport ? "visible" : undefined}
      viewport={!reducedMotion && canObserveViewport ? { once: true, margin: "-80px" } : undefined}
      variants={reducedMotion ? undefined : panelVariants}
      transition={{ duration: 0.34, ease: [0.22, 1, 0.36, 1] }}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function MotionList({ children, className, ...props }: MotionProps) {
  const reducedMotion = useReducedMotion();
  const canObserveViewport = typeof window !== "undefined" && "IntersectionObserver" in window;

  return (
    <motion.div
      initial={reducedMotion ? false : "hidden"}
      animate={reducedMotion || !canObserveViewport ? "visible" : undefined}
      whileInView={!reducedMotion && canObserveViewport ? "visible" : undefined}
      viewport={!reducedMotion && canObserveViewport ? { once: true, margin: "-80px" } : undefined}
      variants={reducedMotion ? undefined : listVariants}
      className={className}
      {...props}
    >
      {children}
    </motion.div>
  );
}

export function MotionListItem({ children, className, ...props }: MotionProps) {
  const reducedMotion = useReducedMotion();

  return (
    <motion.div
      variants={reducedMotion ? undefined : itemVariants}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className={cn("motion-reduce:transform-none", className)}
      {...props}
    >
      {children}
    </motion.div>
  );
}
