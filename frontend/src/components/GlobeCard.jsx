import { useEffect, useRef, useState } from "react";
import Globe from "globe.gl";
import { Color } from "three";
import { feature } from "topojson-client";
import countriesTopology from "world-atlas/countries-110m.json";
import PanelState from "./PanelState";
import {
  formatCompactNumber,
  formatPreciseTimestamp,
  formatScore,
  formatTimestamp
} from "../lib/formatters";

const EARTH_TEXTURE_URL = "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-night.jpg";
const EARTH_BUMP_URL = "https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png";
const COUNTRY_FEATURES = feature(countriesTopology, countriesTopology.objects.countries).features;

const HTML_ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => HTML_ESCAPE_MAP[character]);
}

function renderPointLabel(point) {
  const lastReported = point.lastReportedAt
    ? `Reported ${formatPreciseTimestamp(point.lastReportedAt)}`
    : "Report time unavailable";
  const snapshotCaptured = point.sourceSnapshotGeneratedAt
    ? `Feed snapshot ${formatPreciseTimestamp(point.sourceSnapshotGeneratedAt)}`
    : "Snapshot time unavailable";

  return `
    <div class="globe-tooltip__content">
      <span class="globe-tooltip__eyebrow">Malicious IP</span>
      <strong>${escapeHtml(point.ip)}</strong>
      <span>Confidence score ${escapeHtml(formatScore(point.score))}</span>
      <span>${escapeHtml(lastReported)}</span>
      <span>${escapeHtml(snapshotCaptured)}</span>
    </div>
  `;
}

function getPointColor(point) {
  const alpha = Math.min(0.95, 0.34 + point.score / 135);
  return `rgba(255, 24, 24, ${alpha})`;
}

function getPointAltitude(point) {
  return 0.004 + point.score / 8000;
}

function getPointRadius(point) {
  return 0.025 + point.score / 2400;
}

export default function GlobeCard({ loading, error, points, count, generatedAt, style }) {
  const globeContainerRef = useRef(null);
  const globeRef = useRef(null);
  const controlsRef = useRef(null);
  const [isRotating, setIsRotating] = useState(true);
  const isRotatingRef = useRef(true);

  useEffect(() => {
    if (!globeContainerRef.current || globeRef.current) {
      return undefined;
    }

    const globe = new Globe(globeContainerRef.current, {
      animateIn: true,
      waitForGlobeReady: false
    })
      .globeImageUrl(EARTH_TEXTURE_URL)
      .bumpImageUrl(EARTH_BUMP_URL)
      .backgroundColor("rgba(0,0,0,0)")
      .showAtmosphere(true)
      .atmosphereColor("#3ba8ff")
      .atmosphereAltitude(0.16)
      .showGraticules(false)
      .pointsTransitionDuration(1400)
      .pointColor(getPointColor)
      .pointAltitude(getPointAltitude)
      .pointRadius(getPointRadius)
      .pointResolution(10)
      .pointLabel(renderPointLabel)
      .polygonsData(COUNTRY_FEATURES)
      .polygonCapColor(() => "rgba(14, 28, 52, 0.14)")
      .polygonSideColor(() => "rgba(0, 0, 0, 0)")
      .polygonStrokeColor(() => "rgba(164, 201, 255, 0.42)")
      .polygonAltitude(0.002)
      .polygonsTransitionDuration(0)
      .pointOfView({ lat: 22, lng: 12, altitude: 1.05 });

    const globeMaterial = globe.globeMaterial?.();
    if (globeMaterial) {
      globeMaterial.color = new Color("#dce7ff");
      globeMaterial.emissive = new Color("#07111f");
      globeMaterial.emissiveIntensity = 0.18;
      globeMaterial.bumpScale = 0.55;
      globeMaterial.shininess = 6;
    }

    const syncDimensions = () => {
      if (!globeContainerRef.current) {
        return;
      }

      const { width, height } = globeContainerRef.current.getBoundingClientRect();
      if (width > 0 && height > 0) {
        globe.width(width).height(height);
      }
    };

    let controlsFrameId = null;
    const configureControls = () => {
      const controls = globe.controls?.();

      if (!controls) {
        controlsFrameId = window.requestAnimationFrame(configureControls);
        return;
      }

      controlsRef.current = controls;
      controls.autoRotate = isRotatingRef.current;
      controls.autoRotateSpeed = 0.45;
      controls.enablePan = false;
      controls.enableDamping = true;
      controls.minDistance = 160;
      controls.maxDistance = 600;
    };

    syncDimensions();
    configureControls();

    let resizeObserver;
    if (typeof ResizeObserver !== "undefined") {
      resizeObserver = new ResizeObserver(syncDimensions);
      resizeObserver.observe(globeContainerRef.current);
    } else {
      window.addEventListener("resize", syncDimensions);
    }

    globeRef.current = globe;

    return () => {
      if (controlsFrameId !== null) {
        window.cancelAnimationFrame(controlsFrameId);
      }

      resizeObserver?.disconnect();
      window.removeEventListener("resize", syncDimensions);
      controlsRef.current = null;
      globe.pauseAnimation();
      globe._destructor();
      globeRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!globeRef.current) {
      return;
    }

    globeRef.current.pointsData(points);
  }, [points]);

  useEffect(() => {
    isRotatingRef.current = isRotating;

    const controls = controlsRef.current;
    if (!controls) {
      return;
    }

    controls.autoRotate = isRotating;
    controls.update();
  }, [isRotating]);

  let overlay = null;
  if (loading && points.length === 0) {
    overlay = (
      <PanelState variant="loading" message="Syncing AbuseIPDB blacklist coordinates for the globe." />
    );
  } else if (error && points.length === 0) {
    overlay = <PanelState variant="error" message={error} />;
  } else if (!loading && !error && points.length === 0) {
    overlay = (
      <PanelState
        variant="empty"
        message="The blacklist is currently empty, so there are no points to render."
      />
    );
  }

  return (
    <section className="panel globe-card" style={style}>
      <header className="globe-card__header">
        <div>
          <span className="panel-kicker">AbuseIPDB geolocation feed</span>
          <h2 className="globe-card__title">Global Threat Globe</h2>
          <p className="globe-card__subtitle">
            Hover live blacklist nodes to inspect IP confidence and last reported activity.
          </p>
        </div>
        <div className="globe-card__metrics">
          <div className="metric-tile">
            <span className="metric-tile__label">Threat nodes</span>
            <strong className="metric-tile__value">{formatCompactNumber(count)}</strong>
          </div>
          <div className="metric-tile">
            <span className="metric-tile__label">Snapshot generated</span>
            <strong className="metric-tile__value">{formatTimestamp(generatedAt)}</strong>
          </div>
        </div>
      </header>

      <div className="globe-card__stage">
        <div ref={globeContainerRef} className="globe-card__canvas" />
        {overlay ? <div className="globe-card__overlay">{overlay}</div> : null}

        <div className="globe-card__legend">
          <span className="legend-dot" />
          <span>Red nodes indicate malicious IP coordinates.</span>
          <span className="legend-divider" />
          <span>Node height scales with abuse confidence.</span>
        </div>

        <button
          type="button"
          className="globe-card__toggle"
          onClick={() => setIsRotating((current) => !current)}
        >
          {isRotating ? "Stop Rotation" : "Start Rotation"}
        </button>
      </div>
    </section>
  );
}
