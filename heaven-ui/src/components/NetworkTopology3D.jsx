import { useRef, useMemo, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Html, Stars } from '@react-three/drei'
import * as THREE from 'three'

// three.js materials need real hex colors (CSS vars can't reach the GPU),
// so the premium palette is mirrored here as literals.
const SEV_COLORS = {
  critical: '#FF4D6A', high: '#FF8A3D', medium: '#FFC53D',
  low: '#38BDF8', info: '#8593AD', unknown: '#6D7CFF',
}
const ACCENT = '#6D7CFF'
const ACCENT_2 = '#A78BFA'

function Edge({ start, end, color }) {
  const ref = useRef()
  const points = useMemo(() => [
    new THREE.Vector3(...start),
    new THREE.Vector3(...end),
  ], [start, end])
  const geo = useMemo(() => new THREE.BufferGeometry().setFromPoints(points), [points])

  useFrame(({ clock }) => {
    if (ref.current) {
      ref.current.material.opacity = 0.12 + 0.06 * Math.sin(clock.elapsedTime * 2 + start[0])
    }
  })

  return (
    <line ref={ref} geometry={geo}>
      <lineBasicMaterial color={color || ACCENT} transparent opacity={0.18} />
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
          emissiveIntensity={hovered ? 0.9 : 0.35}
          transparent opacity={0.9}
          wireframe={hovered}
        />
      </mesh>

      <mesh ref={ring} position={position} rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius * 1.6, 0.012, 8, 32]} />
        <meshBasicMaterial color={color} transparent opacity={hovered ? 0.7 : 0.22} />
      </mesh>

      {hovered && (
        <Html position={[position[0], position[1] + radius + 0.3, position[2]]}
              style={{ pointerEvents: 'none' }}>
          <div style={{
            background: 'rgba(11,15,26,0.94)',
            border: `1px solid ${color}`,
            borderRadius: 8,
            color: '#ECEFF7',
            padding: '7px 11px',
            fontSize: '11px',
            fontFamily: 'JetBrains Mono, monospace',
            whiteSpace: 'nowrap',
            boxShadow: `0 8px 24px rgba(0,0,0,0.5), 0 0 16px ${color}55`,
          }}>
            <div style={{ color, fontWeight: 700 }}>{host.ip || host.host || 'unknown'}</div>
            <div style={{ color: '#9BA7C0', fontSize: 10, marginTop: 2 }}>
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
    <gridHelper args={[20, 20, '#1b2336', '#141a28']} position={[0, -2, 0]} />
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
      <ambientLight intensity={0.12} />
      <pointLight position={[0, 5, 0]} intensity={0.6} color={ACCENT} />
      <pointLight position={[-5, -2, -5]} intensity={0.35} color={ACCENT_2} />
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
      <div style={{
        position: 'absolute', top: 12, right: 14, zIndex: 10,
        fontSize: 11, color: 'var(--text-2)', letterSpacing: '0.06em',
      }}>
        {hasHosts
          ? <><span style={{ color: 'var(--brand)' }}>●</span> {hosts.length} host{hosts.length !== 1 ? 's' : ''} mapped</>
          : <span style={{ textTransform: 'uppercase' }}>○ no hosts — run a scan</span>}
      </div>

      <Canvas
        camera={{ position: [0, 2, 8], fov: 55 }}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <Scene hosts={hosts} onSelect={setSelected} />
      </Canvas>

      {selected && (
        <div className="card-glass" style={{
          position: 'absolute', bottom: 14, left: 14, right: 14,
          padding: '10px 14px', borderRadius: 'var(--radius-md)',
          fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-0)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <span>
            <span style={{ color: SEV_COLORS[selected.severity || 'unknown'] }}>●</span>
            {' '}{selected.ip || selected.host}
            {' · '}{selected.open_ports?.join(', ') || '—'}
          </span>
          <button
            onClick={() => setSelected(null)}
            style={{ background: 'none', border: 'none', color: 'var(--text-2)', cursor: 'pointer', fontSize: 14 }}
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
