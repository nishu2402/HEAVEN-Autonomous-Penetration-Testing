import { useRef, useMemo, useState, useEffect } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Html, Stars } from '@react-three/drei'
import * as THREE from 'three'

const SEV_COLORS = {
  critical: '#FF003C', high: '#FF6B00', medium: '#FFB800',
  low: '#00D4FF', info: '#00FF41', unknown: '#00FF41',
}

function Edge({ start, end, color }) {
  const ref = useRef()
  const points = useMemo(() => [
    new THREE.Vector3(...start),
    new THREE.Vector3(...end),
  ], [start, end])
  const geo = useMemo(() => new THREE.BufferGeometry().setFromPoints(points), [points])

  useFrame(({ clock }) => {
    if (ref.current) {
      ref.current.material.opacity = 0.1 + 0.05 * Math.sin(clock.elapsedTime * 2 + start[0])
    }
  })

  return (
    <line ref={ref} geometry={geo}>
      <lineBasicMaterial color={color || '#00FF41'} transparent opacity={0.15} />
    </line>
  )
}

function HostNode({ host, position, severity, portCount, onClick }) {
  const mesh = useRef()
  const ring = useRef()
  const [hovered, setHovered] = useState(false)
  const color = SEV_COLORS[severity] || SEV_COLORS.unknown
  const radius = 0.12 + Math.min(portCount * 0.025, 0.35)

  useFrame(({ clock }) => {
    if (!mesh.current) return
    const t = clock.elapsedTime
    mesh.current.position.y = position[1] + Math.sin(t * 0.7 + position[0] * 2) * 0.06
    mesh.current.rotation.y = t * 0.3
    if (ring.current) {
      ring.current.rotation.z = t * 0.5
      ring.current.scale.setScalar(hovered ? 1.3 : 1.0)
    }
  })

  return (
    <group>
      <mesh
        ref={mesh}
        position={position}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
        onClick={() => onClick && onClick(host)}
      >
        <icosahedronGeometry args={[radius, 1]} />
        <meshStandardMaterial
          color={color} emissive={color}
          emissiveIntensity={hovered ? 0.8 : 0.3}
          transparent opacity={0.85}
          wireframe={hovered}
        />
      </mesh>

      {/* Ring */}
      <mesh ref={ring} position={position} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius * 1.6, 0.012, 8, 32]} />
        <meshBasicMaterial color={color} transparent opacity={hovered ? 0.6 : 0.2} />
      </mesh>

      {hovered && (
        <Html position={[position[0], position[1] + radius + 0.3, position[2]]}
              style={{ pointerEvents: 'none' }}>
          <div style={{
            background: 'rgba(0,0,0,0.92)',
            border: `1px solid ${color}`,
            color: '#00FF41',
            padding: '6px 10px',
            fontSize: '11px',
            fontFamily: 'monospace',
            whiteSpace: 'nowrap',
            boxShadow: `0 0 12px ${color}44`,
          }}>
            <div style={{ color, fontWeight: 700 }}>{host.ip || host.host || 'unknown'}</div>
            <div style={{ color: 'rgba(0,255,65,0.6)', fontSize: 10, marginTop: 2 }}>
              {severity?.toUpperCase()} · {portCount} port{portCount !== 1 ? 's' : ''}
            </div>
          </div>
        </Html>
      )}
    </group>
  )
}

function GridPlane() {
  return (
    <gridHelper args={[20, 20, 'rgba(0,255,65,0.05)', 'rgba(0,255,65,0.05)']}
                position={[0, -2, 0]} />
  )
}

function Scene({ hosts, onSelect }) {
  const positions = useMemo(() => {
    return hosts.map((_, i) => {
      const angle = (i / hosts.length) * Math.PI * 2
      const r = 1.5 + (i % 3) * 1.2
      return [
        Math.cos(angle) * r,
        (Math.random() - 0.5) * 1.5,
        Math.sin(angle) * r,
      ]
    })
  }, [hosts.length])

  const edges = useMemo(() => {
    const out = []
    for (let i = 0; i < positions.length; i++) {
      const j = (i + 1) % positions.length
      out.push({ start: positions[i], end: positions[j] })
      if (i > 0 && i % 3 === 0) {
        const k = Math.floor(Math.random() * i)
        out.push({ start: positions[i], end: positions[k] })
      }
    }
    return out
  }, [positions])

  return (
    <>
      <ambientLight intensity={0.1} />
      <pointLight position={[0, 5, 0]} intensity={0.5} color="#00FF41" />
      <pointLight position={[-5, -2, -5]} intensity={0.3} color="#00D4FF" />
      <Stars radius={30} depth={20} count={300} factor={2} saturation={0} fade speed={0.5} />
      <GridPlane />
      {edges.map((e, i) => (
        <Edge key={i} start={e.start} end={e.end} />
      ))}
      {hosts.map((host, i) => (
        <HostNode
          key={host.ip || host.host || i}
          host={host}
          position={positions[i]}
          severity={host.severity || host.max_severity || 'unknown'}
          portCount={host.open_ports?.length || 1}
          onClick={onSelect}
        />
      ))}
      <OrbitControls
        enableZoom={true} enablePan={false}
        minDistance={3} maxDistance={15}
        autoRotate autoRotateSpeed={0.4}
        makeDefault
      />
    </>
  )
}

export default function NetworkTopology3D({ hosts = [] }) {
  const [selected, setSelected] = useState(null)
  const hasHosts = hosts.length > 0

  return (
    <div className="topology-container">
      {hasHosts ? (
        <div style={{
          position: 'absolute', top: 8, right: 10, zIndex: 10,
          fontSize: 11, color: 'rgba(0,255,65,0.65)',
          letterSpacing: '0.1em',
        }}>
          ● {hosts.length} host{hosts.length !== 1 ? 's' : ''} mapped
        </div>
      ) : (
        <div style={{
          position: 'absolute', top: 8, right: 10, zIndex: 10,
          fontSize: 10, color: 'rgba(0,255,65,0.55)',
          letterSpacing: '0.1em', textTransform: 'uppercase',
        }}>
          ○ no hosts — run a scan
        </div>
      )}

      <Canvas
        camera={{ position: [0, 2, 8], fov: 55 }}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <Scene hosts={hosts} onSelect={setSelected} />
      </Canvas>

      {selected && (
        <div style={{
          position: 'absolute', bottom: 12, left: 12, right: 12,
          background: 'rgba(0,0,0,0.9)',
          border: '1px solid rgba(0,255,65,0.3)',
          padding: '8px 12px',
          fontSize: 11,
          fontFamily: 'monospace',
          color: '#00FF41',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <span>
            <span style={{ color: SEV_COLORS[selected.severity || 'unknown'] }}>●</span>
            {' '}{selected.ip || selected.host}
            {' · '}{selected.open_ports?.join(', ') || '—'}
          </span>
          <button
            onClick={() => setSelected(null)}
            style={{ background: 'none', border: 'none', color: 'rgba(0,255,65,0.4)', cursor: 'pointer', fontSize: 12 }}
          >✕</button>
        </div>
      )}

      <div className="topology-legend">
        {Object.entries(SEV_COLORS).slice(0, 5).map(([sev, col]) => (
          <span key={sev}>
            <span className="legend-dot" style={{ background: col }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  )
}
