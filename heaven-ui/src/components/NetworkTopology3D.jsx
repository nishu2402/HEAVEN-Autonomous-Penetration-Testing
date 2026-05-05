import { useRef, useMemo, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Html } from '@react-three/drei'
import * as THREE from 'three'

const SEV_COLORS = {
  critical: '#FF003C', high: '#FF6B00', medium: '#FFB800',
  low: '#00D4FF', info: '#00FF41', unknown: '#00FF41',
}

function HostNode({ host, position, severity, portCount, hovered, onHover }) {
  const mesh = useRef()
  const radius = 0.15 + Math.min(portCount * 0.03, 0.4)
  const color = SEV_COLORS[severity] || SEV_COLORS.unknown

  useFrame((state) => {
    if (mesh.current) {
      mesh.current.position.y = position[1] + Math.sin(state.clock.elapsedTime * 0.8 + position[0]) * 0.05
    }
  })

  return (
    <group>
      <mesh ref={mesh} position={position}
            onPointerOver={() => onHover(host)}
            onPointerOut={() => onHover(null)}>
        <sphereGeometry args={[radius, 16, 16]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.4}
                              transparent opacity={0.9} />
      </mesh>
      {hovered === host && (
        <Html position={[position[0], position[1] + radius + 0.2, position[2]]}>
          <div style={{
            background: 'rgba(0,0,0,0.85)',
            border: '1px solid #00FF41',
            color: '#00FF41',
            padding: '4px 8px',
            fontSize: '11px',
            fontFamily: 'monospace',
            whiteSpace: 'nowrap',
          }}>
            {host.ip || host.host}<br/>
            <span style={{color: SEV_COLORS[severity]}}>
              {severity?.toUpperCase()} · {portCount} ports
            </span>
          </div>
        </Html>
      )}
    </group>
  )
}

function Edges({ positions }) {
  const lines = useMemo(() => {
    const pts = []
    for (let i = 0; i < positions.length - 1; i++) {
      pts.push(new THREE.Vector3(...positions[i]))
      pts.push(new THREE.Vector3(...positions[i + 1]))
    }
    return pts
  }, [positions])

  if (lines.length === 0) return null
  const geometry = new THREE.BufferGeometry().setFromPoints(lines)
  return (
    <lineSegments geometry={geometry}>
      <lineBasicMaterial color="#00FF41" opacity={0.15} transparent />
    </lineSegments>
  )
}

function Scene({ hosts, hovered, onHover }) {
  const positions = useMemo(() => {
    return hosts.map((_, i) => {
      const angle = (i / hosts.length) * Math.PI * 2
      const r = 2 + Math.floor(i / 8) * 1.5
      return [Math.cos(angle) * r, (Math.random() - 0.5) * 2, Math.sin(angle) * r]
    })
  }, [hosts.length])

  return (
    <>
      <ambientLight intensity={0.1} color="#001a00" />
      <pointLight position={[0, 5, 0]} intensity={0.5} color="#00D4FF" />
      <pointLight position={[0, -5, 0]} intensity={0.3} color="#00FF41" />
      <Edges positions={positions} />
      {hosts.map((host, i) => (
        <HostNode key={host.ip || host.host || i}
                  host={host}
                  position={positions[i]}
                  severity={host.severity || 'unknown'}
                  portCount={(host.open_ports || []).length}
                  hovered={hovered}
                  onHover={onHover} />
      ))}
      <OrbitControls enablePan={false} minDistance={2} maxDistance={20}
                     autoRotate autoRotateSpeed={0.4} />
    </>
  )
}

export default function NetworkTopology3D({ hosts = [] }) {
  const [hovered, setHovered] = useState(null)

  if (!hosts.length) {
    return (
      <div style={{ height: '100%', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', color: '#1a4a1a', fontSize: '12px' }}>
        NO HOSTS MAPPED
      </div>
    )
  }

  return (
    <Canvas camera={{ position: [0, 3, 8], fov: 60 }}
            style={{ background: '#000' }}>
      <Scene hosts={hosts} hovered={hovered} onHover={setHovered} />
    </Canvas>
  )
}
