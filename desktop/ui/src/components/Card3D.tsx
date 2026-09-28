import React from 'react';

interface Card3DProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  glare?: boolean;
  depth?: number;
  onClick?: () => void;
}

/**
 * Enterprise Solid Card Component
 * Fully stationary - NO movable icons, NO tilting, NO wobbling.
 * Provides clean enterprise styling with crisp hover borders and zero distraction.
 */
export default function Card3D({
  children,
  className = '',
  style = {},
  onClick,
}: Card3DProps) {
  return (
    <div
      className={`card-static-wrapper ${className}`}
      onClick={onClick}
      style={{
        position: 'relative',
        height: '100%',
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        ...style,
      }}
    >
      {children}
    </div>
  );
}
