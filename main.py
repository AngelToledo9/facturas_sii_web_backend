from datetime import datetime, date
from typing import List, Optional

from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel
from sqlalchemy import (
    Column,
    Integer,
    String,
    Date,
    DateTime,
    create_engine,
    func,
    or_,
    Boolean,
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

# -----------------------------
# Configuración base de datos
# -----------------------------

DATABASE_URL = "sqlite:///./facturas.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Contexto de hashing de contraseñas
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


class Factura(Base):
    __tablename__ = "facturas"

    id = Column(Integer, primary_key=True, index=True)
    codigo_barra = Column(String, nullable=False)

    rut_emisor = Column(String, index=True)
    rut_receptor = Column(String, index=True)
    tipo_documento = Column(String, index=True)
    folio = Column(Integer, index=True)
    fecha_emision = Column(Date, index=True)
    monto_total = Column(Integer)

    estado = Column(String, default="VALIDADA")
    fecha_registro = Column(DateTime, default=datetime.utcnow)

    nota_interna = Column(String, nullable=True)


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    rol = Column(String, default="USUARIO")  # ADMIN, CONTADOR, USUARIO

    # Permisos granulares
    puede_escanear = Column(Boolean, default=True)
    puede_ver_listado = Column(Boolean, default=False)
    puede_ver_dashboard = Column(Boolean, default=False)
    puede_exportar = Column(Boolean, default=False)
    puede_gestionar_usuarios = Column(Boolean, default=False)

    activo = Column(Boolean, default=True)


Base.metadata.create_all(bind=engine)


def crear_usuarios_demo():
    """Crea usuarios de prueba si la tabla está vacía."""
    db = SessionLocal()
    try:
        if not db.query(Usuario).first():
            admin = Usuario(
                username="admin",
                hashed_password=pwd_context.hash("admin123"),
                rol="ADMIN",
                puede_escanear=True,
                puede_ver_listado=True,
                puede_ver_dashboard=True,
                puede_exportar=True,
                puede_gestionar_usuarios=True,
                activo=True,
            )
            contador = Usuario(
                username="contador",
                hashed_password=pwd_context.hash("contador123"),
                rol="CONTADOR",
                puede_escanear=True,
                puede_ver_listado=True,
                puede_ver_dashboard=True,
                puede_exportar=True,
                puede_gestionar_usuarios=False,
                activo=True,
            )
            usuario = Usuario(
                username="usuario",
                hashed_password=pwd_context.hash("usuario123"),
                rol="USUARIO",
                puede_escanear=True,
                puede_ver_listado=False,
                puede_ver_dashboard=False,
                puede_exportar=False,
                puede_gestionar_usuarios=False,
                activo=True,
            )
            db.add_all([admin, contador, usuario])
            db.commit()
    finally:
        db.close()


crear_usuarios_demo()

# -----------------------------
# Esquemas Pydantic
# -----------------------------


class FacturaOut(BaseModel):
    id: int
    codigo_barra: str
    rut_emisor: str
    rut_receptor: str
    tipo_documento: str
    folio: int
    fecha_emision: date
    monto_total: int
    estado: str
    fecha_registro: datetime
    nota_interna: Optional[str] = None

    class Config:
        orm_mode = True


class FacturaListadoOut(BaseModel):
    id: int
    rut_emisor: str
    rut_receptor: str
    tipo_documento: str
    folio: int
    fecha_emision: date
    monto_total: int
    estado: str

    class Config:
        orm_mode = True


class ValidarFacturaIn(BaseModel):
    codigo_barra: str


# -----------------------------
# Dependencia de sesión DB
# -----------------------------


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------
# Lógica para parsear código SII
# -----------------------------


def parsear_codigo_sii(codigo: str) -> dict:
    """
    Espera algo como:
    RUTEmisor=76.543.210-5|RUTReceptor=12.345.678-9|
    TD=33|F=12345|FE=2025-11-11|MNT=15990
    """
    partes = codigo.split("|")
    data = {}
    for parte in partes:
        if "=" in parte:
            k, v = parte.split("=", 1)
            data[k.strip()] = v.strip()

    campos_obligatorios = ["RUTEmisor", "RUTReceptor", "TD", "F", "FE", "MNT"]
    for c in campos_obligatorios:
        if c not in data:
            raise ValueError(f"Falta el campo obligatorio: {c}")

    return data


# -----------------------------
# Inicializar FastAPI + plantillas + sesiones
# -----------------------------

app = FastAPI(
    title="API Facturas SII",
    description="Backend para lectura y registro de facturas SII",
    version="0.1.0",
)
app = FastAPI(
    title="API Facturas SII",
    description="Backend para lectura y registro de facturas SII",
    version="0.1.0",
)

# Servir archivos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

# Clave de sesiones (puedes cambiarla por otra cadena)
app.add_middleware(SessionMiddleware, secret_key="cambia-esta-clave-super-secreta")

templates = Jinja2Templates(directory="templates")


# -----------------------------
# Helpers de autenticación / permisos
# -----------------------------


def verificar_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def autenticar_usuario(db: Session, username: str, password: str) -> Optional[Usuario]:
    user = db.query(Usuario).filter(Usuario.username == username).first()
    if not user:
        return None
    if not verificar_password(password, user.hashed_password):
        return None
    if not user.activo:
        return None
    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Usuario:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")

    usuario = (
        db.query(Usuario)
        .filter(Usuario.id == user_id, Usuario.activo == True)
        .first()
    )
    if not usuario:
        raise HTTPException(status_code=401, detail="Usuario no válido")

    return usuario


def require_perm(nombre_perm: str):
    """
    Devuelve una dependencia que exige que el usuario tenga un permiso booleano.
    Ejemplo en ruta:
    usuario: Usuario = Depends(require_perm("puede_ver_listado"))
    """
    def dep(usuario: Usuario = Depends(get_current_user)):
        if not getattr(usuario, nombre_perm, False):
            raise HTTPException(status_code=403, detail="No autorizado")
        return usuario

    return dep


def usuario_to_context(usuario: Usuario) -> dict:
    """Devuelve un dict sencillo para pasar al template."""
    return {"username": usuario.username, "rol": usuario.rol}


# -----------------------------
# Rutas HTML (interfaz web)
# -----------------------------


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = autenticar_usuario(db, username, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Usuario o contraseña incorrectos"},
        )

    # Guardamos en sesión el id (y de paso username/rol por comodidad)
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["rol"] = user.rol

    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def formulario_escanear(
    request: Request,
    usuario: Usuario = Depends(require_perm("puede_escanear")),
):
    return templates.TemplateResponse(
        "escanear.html",
        {
            "request": request,
            "factura": None,
            "error": None,
            "codigo_barra": "",
            "usuario": usuario_to_context(usuario),
        },
    )


@app.post("/", response_class=HTMLResponse)
@app.post("/escanear", response_class=HTMLResponse)
def escanear_factura(
    request: Request,
    codigo_barra: str = Form(...),
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(require_perm("puede_escanear")),
):
    factura = None
    error = None

    try:
        datos = parsear_codigo_sii(codigo_barra)
        fecha_emision = datetime.strptime(datos["FE"], "%Y-%m-%d").date()
        folio = int(datos["F"])
        monto_total = int(datos["MNT"])

        factura = Factura(
            codigo_barra=codigo_barra,
            rut_emisor=datos["RUTEmisor"],
            rut_receptor=datos["RUTReceptor"],
            tipo_documento=datos["TD"],
            folio=folio,
            fecha_emision=fecha_emision,
            monto_total=monto_total,
            estado="VALIDADA",
        )

        db.add(factura)
        db.commit()
        db.refresh(factura)

    except ValueError as e:
        error = str(e)
    except Exception:
        error = "Ocurrió un error al procesar el código. Verifique el formato."

    return templates.TemplateResponse(
        "escanear.html",
        {
            "request": request,
            "factura": factura,
            "error": error,
            "codigo_barra": codigo_barra,
            "usuario": usuario_to_context(usuario),
        },
    )


@app.get("/listado", response_class=HTMLResponse)
def pagina_listado(
    request: Request,
    rut: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    folio: Optional[str] = None,
    monto_min: Optional[str] = None,
    monto_max: Optional[str] = None,
    texto: Optional[str] = None,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(require_perm("puede_ver_listado")),
):
    query = db.query(Factura)

    if rut:
        query = query.filter(Factura.rut_emisor == rut)

    if fecha_desde:
        try:
            f_desde = datetime.strptime(fecha_desde, "%Y-%m-%d").date()
            query = query.filter(Factura.fecha_emision >= f_desde)
        except Exception:
            pass

    if fecha_hasta:
        try:
            f_hasta = datetime.strptime(fecha_hasta, "%Y-%m-%d").date()
            query = query.filter(Factura.fecha_emision <= f_hasta)
        except Exception:
            pass

    if folio:
        try:
            folio_int = int(folio)
            query = query.filter(Factura.folio == folio_int)
        except ValueError:
            pass

    if monto_min:
        try:
            monto_min_int = int(monto_min)
            query = query.filter(Factura.monto_total >= monto_min_int)
        except ValueError:
            pass

    if monto_max:
        try:
            monto_max_int = int(monto_max)
            query = query.filter(Factura.monto_total <= monto_max_int)
        except ValueError:
            pass

    if texto:
        patron = f"%{texto}%"
        query = query.filter(
            or_(
                Factura.codigo_barra.like(patron),
                Factura.nota_interna.like(patron),
            )
        )

    facturas = query.order_by(Factura.fecha_emision.desc(), Factura.id.desc()).all()

    return templates.TemplateResponse(
        "listado.html",
        {
            "request": request,
            "facturas": facturas,
            "rut": rut,
            "fecha_desde": fecha_desde,
            "fecha_hasta": fecha_hasta,
            "folio": folio,
            "monto_min": monto_min,
            "monto_max": monto_max,
            "texto": texto,
            "usuario": usuario_to_context(usuario),
        },
    )


@app.get("/factura/{factura_id}", response_class=HTMLResponse)
def detalle_factura_html(
    factura_id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(require_perm("puede_ver_listado")),
):
    factura = db.query(Factura).filter(Factura.id == factura_id).first()
    if not factura:
        return HTMLResponse("<h1>Factura no encontrada</h1>", status_code=404)

    return templates.TemplateResponse(
        "escanear.html",
        {
            "request": request,
            "factura": factura,
            "error": None,
            "codigo_barra": factura.codigo_barra,
            "usuario": usuario_to_context(usuario),
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(require_perm("puede_ver_dashboard")),
):
    total_general = db.query(
        func.coalesce(func.sum(Factura.monto_total), 0)
    ).scalar()

    cantidad_facturas = db.query(func.count(Factura.id)).scalar()

    filas_mes = (
        db.query(
            func.strftime("%Y-%m", Factura.fecha_emision).label("mes"),
            func.sum(Factura.monto_total).label("total"),
        )
        .group_by("mes")
        .order_by("mes")
        .all()
    )

    labels_mes = [f.mes for f in filas_mes]
    values_mes = [f.total for f in filas_mes]

    filas_emisor = (
        db.query(
            Factura.rut_emisor.label("rut"),
            func.sum(Factura.monto_total).label("total"),
        )
        .group_by(Factura.rut_emisor)
        .order_by(func.sum(Factura.monto_total).desc())
        .limit(5)
        .all()
    )

    labels_emisor = [f.rut for f in filas_emisor]
    values_emisor = [f.total for f in filas_emisor]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total_general": total_general,
            "cantidad_facturas": cantidad_facturas,
            "labels_mes": labels_mes,
            "values_mes": values_mes,
            "labels_emisor": labels_emisor,
            "values_emisor": values_emisor,
            "usuario": usuario_to_context(usuario),
        },
    )


@app.get("/exportar_csv")
def exportar_csv(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(require_perm("puede_exportar")),
):
    facturas = db.query(Factura).order_by(Factura.fecha_emision.desc()).all()

    lineas = []
    lineas.append(
        "id,rut_emisor,rut_receptor,tipo_documento,folio,fecha_emision,"
        "monto_total,estado,fecha_registro"
    )

    for f in facturas:
        linea = ",".join(
            [
                str(f.id),
                f.rut_emisor or "",
                f.rut_receptor or "",
                f.tipo_documento or "",
                str(f.folio),
                f.fecha_emision.isoformat() if f.fecha_emision else "",
                str(f.monto_total),
                f.estado or "",
                f.fecha_registro.isoformat() if f.fecha_registro else "",
            ]
        )
        lineas.append(linea)

    contenido = "\n".join(lineas)

    return Response(
        content=contenido,
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="facturas_sii.csv"'
        },
    )


# -----------------------------
# Administración de usuarios (HTML)
# -----------------------------


@app.get("/admin/usuarios", response_class=HTMLResponse)
def admin_listar_usuarios(
    request: Request,
    db: Session = Depends(get_db),
    usuario_actual: Usuario = Depends(require_perm("puede_gestionar_usuarios")),
):
    usuarios = db.query(Usuario).order_by(Usuario.id).all()
    return templates.TemplateResponse(
        "admin_usuarios.html",
        {
            "request": request,
            "usuarios": usuarios,
            "usuario": usuario_to_context(usuario_actual),
        },
    )


@app.get("/admin/usuarios/nuevo", response_class=HTMLResponse)
def admin_nuevo_usuario_form(
    request: Request,
    usuario_actual: Usuario = Depends(require_perm("puede_gestionar_usuarios")),
):
    return templates.TemplateResponse(
        "admin_usuario_form.html",
        {
            "request": request,
            "modo": "nuevo",
            "usuario_obj": None,
            "usuario": usuario_to_context(usuario_actual),
        },
    )


@app.get("/admin/usuarios/{usuario_id}/editar", response_class=HTMLResponse)
def admin_editar_usuario_form(
    usuario_id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario_actual: Usuario = Depends(require_perm("puede_gestionar_usuarios")),
):
    usuario_obj = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario_obj:
        return HTMLResponse("<h1>Usuario no encontrado</h1>", status_code=404)

    return templates.TemplateResponse(
        "admin_usuario_form.html",
        {
            "request": request,
            "modo": "editar",
            "usuario_obj": usuario_obj,
            "usuario": usuario_to_context(usuario_actual),
        },
    )


@app.post("/admin/usuarios/guardar", response_class=HTMLResponse)
def admin_guardar_usuario(
    request: Request,
    id: Optional[int] = Form(None),
    username: str = Form(...),
    password: Optional[str] = Form(None),
    rol: str = Form("USUARIO"),
    puede_escanear: Optional[str] = Form(None),
    puede_ver_listado: Optional[str] = Form(None),
    puede_ver_dashboard: Optional[str] = Form(None),
    puede_exportar: Optional[str] = Form(None),
    puede_gestionar_usuarios: Optional[str] = Form(None),
    activo: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    usuario_actual: Usuario = Depends(require_perm("puede_gestionar_usuarios")),
):
    def cb(v: Optional[str]) -> bool:
        return v == "on"

    if id:
        usuario_obj = db.query(Usuario).filter(Usuario.id == id).first()
        if not usuario_obj:
            return HTMLResponse("<h1>Usuario no encontrado</h1>", status_code=404)
    else:
        usuario_obj = Usuario()
        db.add(usuario_obj)

    usuario_obj.username = username
    usuario_obj.rol = rol
    usuario_obj.puede_escanear = cb(puede_escanear)
    usuario_obj.puede_ver_listado = cb(puede_ver_listado)
    usuario_obj.puede_ver_dashboard = cb(puede_ver_dashboard)
    usuario_obj.puede_exportar = cb(puede_exportar)
    usuario_obj.puede_gestionar_usuarios = cb(puede_gestionar_usuarios)
    usuario_obj.activo = cb(activo)

    if password:
        usuario_obj.hashed_password = pwd_context.hash(password)

    db.commit()

    return RedirectResponse(url="/admin/usuarios", status_code=303)


# -----------------------------
# Endpoints API (JSON)
# -----------------------------


@app.post("/facturas/validar", response_model=FacturaOut)
def validar_factura_api(payload: ValidarFacturaIn, db: Session = Depends(get_db)):
    try:
        datos = parsear_codigo_sii(payload.codigo_barra)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fecha_emision = datetime.strptime(datos["FE"], "%Y-%m-%d").date()
        folio = int(datos["F"])
        monto_total = int(datos["MNT"])
    except Exception:
        raise HTTPException(
            status_code=400, detail="Error al convertir fecha, folio o monto."
        )

    factura = Factura(
        codigo_barra=payload.codigo_barra,
        rut_emisor=datos["RUTEmisor"],
        rut_receptor=datos["RUTReceptor"],
        tipo_documento=datos["TD"],
        folio=folio,
        fecha_emision=fecha_emision,
        monto_total=monto_total,
        estado="VALIDADA",
    )

    db.add(factura)
    db.commit()
    db.refresh(factura)

    return factura



@app.get("/facturas", response_model=List[FacturaListadoOut])
def listar_facturas_api(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(get_current_user),  # solo exige estar autenticado
    rut: Optional[str] = None,
    fecha_desde: Optional[str] = None,
    fecha_hasta: Optional[str] = None,
    folio: Optional[str] = None,
    monto_min: Optional[str] = None,
    monto_max: Optional[str] = None,
    texto: Optional[str] = None,
):
    query = db.query(Factura)

    if rut:
        query = query.filter(Factura.rut_emisor == rut)

    if fecha_desde:
        try:
            f_desde = datetime.strptime(fecha_desde, "%Y-%m-%d").date()
            query = query.filter(Factura.fecha_emision >= f_desde)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="fecha_desde debe tener formato YYYY-MM-DD",
            )

    if fecha_hasta:
        try:
            f_hasta = datetime.strptime(fecha_hasta, "%Y-%m-%d").date()
            query = query.filter(Factura.fecha_emision <= f_hasta)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="fecha_hasta debe tener formato YYYY-MM-DD",
            )

    if folio:
        try:
            folio_int = int(folio)
            query = query.filter(Factura.folio == folio_int)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="folio debe ser un número entero"
            )

    if monto_min:
        try:
            monto_min_int = int(monto_min)
            query = query.filter(Factura.monto_total >= monto_min_int)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="monto_min debe ser un número entero"
            )

    if monto_max:
        try:
            monto_max_int = int(monto_max)
            query = query.filter(Factura.monto_total <= monto_max_int)
        except ValueError:
            raise HTTPException(
                status_code=400, detail="monto_max debe ser un número entero"
            )

    if texto:
        patron = f"%{texto}%"
        query = query.filter(
            or_(
                Factura.codigo_barra.like(patron),
                Factura.nota_interna.like(patron),
            )
        )

    query = query.order_by(Factura.fecha_emision.desc(), Factura.id.desc())

    return query.all()
