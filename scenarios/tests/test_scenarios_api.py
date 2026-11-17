import pytest
from rest_framework import status
from scenarios.models import AttackScenario, SimulationLog


@pytest.mark.django_db
class TestScenarioListingAndFiltering:
    """Тести для перегляду списку та фільтрації сценаріїв (GET /api/scenarios/)."""

    def test_guest_can_only_see_published_scenarios(
        self, api_client, published_scenario, draft_scenario
    ):
        """Гість бачить тільки опубліковані сценарії."""
        response = api_client.get('/api/scenarios/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]['id'] == published_scenario.id
        assert data[0]['is_published'] is True

    def test_student_sees_published_and_own_drafts(
        self, student_client, published_scenario, draft_scenario, other_draft_scenario
    ):
        """Студент бачить опубліковані сценарії та власні чернетки, але не чужі чернетки."""
        response = student_client.get('/api/scenarios/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        scenario_ids = [item['id'] for item in data]
        assert published_scenario.id in scenario_ids
        assert draft_scenario.id in scenario_ids
        assert other_draft_scenario.id not in scenario_ids

    def test_admin_sees_all_scenarios(
        self, admin_client, published_scenario, draft_scenario, other_draft_scenario
    ):
        """Адміністратор бачить абсолютно всі сценарії (публічні та всі чернетки)."""
        response = admin_client.get('/api/scenarios/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        scenario_ids = [item['id'] for item in data]
        assert published_scenario.id in scenario_ids
        assert draft_scenario.id in scenario_ids
        assert other_draft_scenario.id in scenario_ids

    def test_filter_by_vulnerability_type(
        self, admin_client, published_scenario, draft_scenario
    ):
        """Фільтрація списку сценаріїв за типом вразливості."""
        response = admin_client.get('/api/scenarios/?vulnerability_type=SQLI')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]['vulnerability_type'] == 'SQLI'

    def test_filter_by_severity(
        self, admin_client, published_scenario, draft_scenario
    ):
        """Фільтрація списку сценаріїв за рівнем критичності."""
        response = admin_client.get('/api/scenarios/?severity=HIGH')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]['severity'] == 'HIGH'

    def test_search_by_keyword(
        self, admin_client, published_scenario, draft_scenario
    ):
        """Пошук сценарію за ключовим словом у назві чи описі."""
        response = admin_client.get('/api/scenarios/?search=Comment')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]['id'] == draft_scenario.id


@pytest.mark.django_db
class TestScenarioDetailRetrieval:
    """Тести для отримання деталей сценарію (GET /api/scenarios/{id}/)."""

    def test_guest_can_retrieve_published_scenario(self, api_client, published_scenario):
        """Гість може отримати деталі опублікованого сценарію."""
        response = api_client.get(f'/api/scenarios/{published_scenario.id}/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['id'] == published_scenario.id
        assert data['title'] == published_scenario.title

    def test_guest_cannot_retrieve_draft_scenario(self, api_client, draft_scenario):
        """Гість не має доступу до неопублікованого сценарію (401/404)."""
        response = api_client.get(f'/api/scenarios/{draft_scenario.id}/')
        # Оскільки гість не бачить чернетку в get_queryset, повертається 404
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_student_cannot_retrieve_other_users_draft(
        self, student_client, other_draft_scenario
    ):
        """Студент не може отримати чужу неопубліковану чернетку (404 Not Found)."""
        response = student_client.get(f'/api/scenarios/{other_draft_scenario.id}/')
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_owner_can_retrieve_own_draft(self, student_client, draft_scenario):
        """Автор може переглядати свою неопубліковану чернетку."""
        response = student_client.get(f'/api/scenarios/{draft_scenario.id}/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['id'] == draft_scenario.id

    def test_admin_can_retrieve_any_draft(self, admin_client, draft_scenario):
        """Адміністратор може переглядати будь-яку неопубліковану чернетку."""
        response = admin_client.get(f'/api/scenarios/{draft_scenario.id}/')
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['id'] == draft_scenario.id

    def test_retrieve_non_existent_scenario_returns_404(self, admin_client):
        """Запит неіснуючого ідентифікатора повертає 404."""
        response = admin_client.get('/api/scenarios/999999/')
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestScenarioCreation:
    """Тести для створення сценаріїв (POST /api/scenarios/)."""

    def test_unauthenticated_user_cannot_create_scenario(self, api_client):
        """Неавтентифікований користувач (гість) отримує 401 Unauthorized."""
        payload = {
            "title": "CSRF Token Bypass",
            "description": "Тестовий сценарій обходу CSRF захисту.",
            "vulnerability_type": "CSRF",
            "severity": "HIGH",
            "attack_vector": "<form action='http://bank.local/transfer'>",
            "defense_mechanism": "SameSite Cookies та CSRF tokens.",
        }
        response = api_client.post('/api/scenarios/', data=payload, format='json')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_student_can_create_draft_scenario(self, student_client, student_user):
        """Студент може успішно створити новий сценарій (автор призначається автоматично)."""
        payload = {
            "title": "SSRF in Webhook Handler",
            "description": "Можливість запиту внутрішніх метаданих хмари через SSRF.",
            "vulnerability_type": "SSRF",
            "severity": "CRITICAL",
            "attack_vector": "http://169.254.169.254/latest/meta-data/",
            "defense_mechanism": "Білий список дозволених доменів та IP.",
            "defense_active": True,
            "is_published": False,
        }
        response = student_client.post('/api/scenarios/', data=payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data['title'] == payload['title']
        assert data['created_by'] == student_user.id
        assert data['created_by_username'] == student_user.username
        assert data['is_published'] is False

    def test_student_cannot_directly_publish_scenario(self, student_client):
        """Студент отримує 400 Bad Request при спробі опублікувати сценарій без прав адміна."""
        payload = {
            "title": "Unauthorized Publish Attempt",
            "description": "Спроба опублікувати сценарій без перевірки адміністратора.",
            "vulnerability_type": "BAC",
            "severity": "MEDIUM",
            "attack_vector": "payload",
            "defense_mechanism": "defense",
            "is_published": True,
        }
        response = student_client.post('/api/scenarios/', data=payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'is_published' in response.json()

    def test_admin_can_create_published_scenario(self, admin_client, admin_user):
        """Адміністратор може одразу створити опублікований сценарій."""
        payload = {
            "title": "Admin Verified SQLi Scenario",
            "description": "Офіційний верифікований сценарій від викладача.",
            "vulnerability_type": "SQLI",
            "severity": "CRITICAL",
            "attack_vector": "UNION SELECT username, password FROM users --",
            "defense_mechanism": "Prepared statements.",
            "is_published": True,
        }
        response = admin_client.post('/api/scenarios/', data=payload, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()['is_published'] is True
        assert response.json()['created_by'] == admin_user.id

    def test_create_scenario_validation_errors(self, student_client):
        """Валідація обов'язкових полів та довжини назви."""
        # Занадто коротка назва (< 5 символів)
        payload = {
            "title": "SQL",
            "description": "Desc",
            "vulnerability_type": "SQLI",
            "severity": "LOW",
            "attack_vector": "vector",
            "defense_mechanism": "defense",
        }
        response = student_client.post('/api/scenarios/', data=payload, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'title' in response.json()


@pytest.mark.django_db
class TestScenarioUpdating:
    """Тести для оновлення сценаріїв (PUT/PATCH /api/scenarios/{id}/)."""

    def test_unauthenticated_cannot_update_scenario(self, api_client, published_scenario):
        """Гість не може оновлювати сценарій (401 Unauthorized)."""
        response = api_client.patch(
            f'/api/scenarios/{published_scenario.id}/',
            data={'title': 'Hacked Title by Guest'},
            format='json',
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_other_student_cannot_update_scenario(
        self, other_student_client, published_scenario
    ):
        """Інший студент не може змінити чужий сценарій (403 Forbidden)."""
        response = other_student_client.patch(
            f'/api/scenarios/{published_scenario.id}/',
            data={'title': 'Tampered by Other Student'},
            format='json',
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_owner_can_partially_update_scenario(self, student_client, published_scenario):
        """Автор може частково оновити (PATCH) свій сценарій."""
        new_desc = "Оновлений опис сценарію автором."
        response = student_client.patch(
            f'/api/scenarios/{published_scenario.id}/',
            data={'description': new_desc},
            format='json',
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['description'] == new_desc

    def test_owner_can_fully_update_scenario(self, student_client, published_scenario):
        """Автор може повністю оновити (PUT) свій сценарій."""
        payload = {
            "title": "Fully Updated SQL Injection",
            "description": "Повний новий опис.",
            "vulnerability_type": "SQLI",
            "severity": "CRITICAL",
            "attack_vector": "1; DROP TABLE users; --",
            "defense_mechanism": "ORM query parameters.",
            "defense_active": True,
            "is_published": False,
        }
        response = student_client.put(
            f'/api/scenarios/{published_scenario.id}/',
            data=payload,
            format='json',
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['title'] == payload['title']
        assert response.json()['severity'] == 'CRITICAL'

    def test_admin_can_update_any_scenario(self, admin_client, published_scenario):
        """Адміністратор може оновити будь-який сценарій (включаючи чужий)."""
        response = admin_client.patch(
            f'/api/scenarios/{published_scenario.id}/',
            data={'severity': 'LOW'},
            format='json',
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['severity'] == 'LOW'

    def test_update_non_existent_scenario_returns_404(self, admin_client):
        """Оновлення неіснуючого сценарію повертає 404 Not Found."""
        response = admin_client.patch(
            '/api/scenarios/999999/',
            data={'title': 'Non-existent update'},
            format='json',
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestScenarioDeletion:
    """Тести для видалення сценаріїв (DELETE /api/scenarios/{id}/)."""

    def test_unauthenticated_cannot_delete_scenario(self, api_client, published_scenario):
        """Гість не може видаляти сценарій (401 Unauthorized)."""
        response = api_client.delete(f'/api/scenarios/{published_scenario.id}/')
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert AttackScenario.objects.filter(id=published_scenario.id).exists()

    def test_other_student_cannot_delete_scenario(
        self, other_student_client, published_scenario
    ):
        """Інший студент не може видалити чужий сценарій (403 Forbidden)."""
        response = other_student_client.delete(f'/api/scenarios/{published_scenario.id}/')
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert AttackScenario.objects.filter(id=published_scenario.id).exists()

    def test_owner_can_delete_own_scenario(self, student_client, draft_scenario):
        """Автор може успішно видалити власний сценарій (204 No Content)."""
        scenario_id = draft_scenario.id
        response = student_client.delete(f'/api/scenarios/{scenario_id}/')
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not AttackScenario.objects.filter(id=scenario_id).exists()

    def test_admin_can_delete_any_scenario(self, admin_client, published_scenario):
        """Адміністратор може видалити будь-який сценарій."""
        scenario_id = published_scenario.id
        response = admin_client.delete(f'/api/scenarios/{scenario_id}/')
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not AttackScenario.objects.filter(id=scenario_id).exists()

    def test_delete_non_existent_scenario_returns_404(self, admin_client):
        """Спроба видалення неіснуючого сценарію повертає 404 Not Found."""
        response = admin_client.delete('/api/scenarios/999999/')
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestScenarioSimulation:
    """Тести для інтерактивної симуляції атаки (POST /api/scenarios/{id}/simulate/)."""

    def test_unauthenticated_cannot_run_simulation(self, api_client, published_scenario):
        """Неавтентифікований користувач не може запускати симуляцію (401 Unauthorized)."""
        response = api_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data={'payload': "' OR 1=1 --", 'defense_enabled': True},
            format='json',
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_simulation_mitigated_when_defense_enabled(
        self, student_client, student_user, published_scenario
    ):
        """Симуляція з увімкненим захистом нейтралізує атаку (MITIGATED)."""
        payload_data = {
            "payload": "' OR 1=1 --",
            "defense_enabled": True,
        }
        response = student_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data=payload_data,
            format='json',
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['scenario_id'] == published_scenario.id
        assert data['defense_enabled'] is True
        assert data['is_blocked'] is True
        assert data['status'] == 'MITIGATED'
        assert 'simulation_id' in data

        # Перевіряємо створення запису в журналі
        log = SimulationLog.objects.get(id=data['simulation_id'])
        assert log.scenario == published_scenario
        assert log.executed_by == student_user
        assert log.status == SimulationLog.SimulationStatus.MITIGATED

    def test_simulation_breached_when_defense_disabled(
        self, student_client, student_user, published_scenario
    ):
        """Симуляція з вимкненим захистом фіксує прорив (BREACHED)."""
        payload_data = {
            "payload": "' UNION SELECT user, password FROM users --",
            "defense_enabled": False,
        }
        response = student_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data=payload_data,
            format='json',
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data['defense_enabled'] is False
        assert data['is_blocked'] is False
        assert data['status'] == 'BREACHED'

        log = SimulationLog.objects.get(id=data['simulation_id'])
        assert log.status == SimulationLog.SimulationStatus.BREACHED

    def test_simulate_with_empty_payload_returns_400(
        self, student_client, published_scenario
    ):
        """Симуляція з порожнім payload повертає 400 Bad Request."""
        response = student_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data={'payload': '   ', 'defense_enabled': True},
            format='json',
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'payload' in response.json()

    def test_simulate_non_existent_scenario_returns_404(self, student_client):
        """Симуляція для неіснуючого сценарію повертає 404 Not Found."""
        response = student_client.post(
            '/api/scenarios/999999/simulate/',
            data={'payload': 'test', 'defense_enabled': True},
            format='json',
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_simulation_history(
        self, student_client, published_scenario
    ):
        """Отримання історії симуляцій для сценарію."""
        # Запускаємо 2 симуляції
        student_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data={'payload': "payload 1", 'defense_enabled': True},
            format='json',
        )
        student_client.post(
            f'/api/scenarios/{published_scenario.id}/simulate/',
            data={'payload': "payload 2", 'defense_enabled': False},
            format='json',
        )

        response = student_client.get(f'/api/scenarios/{published_scenario.id}/history/')
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2


@pytest.mark.django_db
class TestOpenAPIDocumentationEndpoints:
    """Тести для ендпоінтів документації API та схеми OpenAPI."""

    def test_openapi_schema_endpoint(self, api_client):
        """Ендпоінт /api/schema/ повертає валідну OpenAPI схему."""
        response = api_client.get('/api/schema/')
        assert response.status_code == status.HTTP_200_OK
        # Перевірка наявності ключових елементів OpenAPI схеми в тексті
        content = response.content.decode('utf-8')
        assert 'openapi: 3.0.3' in content
        assert 'SecureFlow API' in content
        assert '/api/scenarios/' in content

    def test_swagger_ui_endpoint(self, api_client):
        """Ендпоінт Swagger UI /api/docs/swagger/ доступний."""
        response = api_client.get('/api/docs/swagger/')
        assert response.status_code == status.HTTP_200_OK
        assert 'swagger-ui' in response.content.decode('utf-8').lower()

    def test_redoc_endpoint(self, api_client):
        """Ендпоінт ReDoc /api/docs/redoc/ доступний."""
        response = api_client.get('/api/docs/redoc/')
        assert response.status_code == status.HTTP_200_OK
        assert 'redoc' in response.content.decode('utf-8').lower()


@pytest.mark.django_db
class TestModelStringRepresentation:
    """Тести для рядкового представлення моделей (__str__)."""

    def test_attack_scenario_str(self, published_scenario):
        """Перевірка __str__ моделі AttackScenario."""
        expected = "SQL Injection in Auth Form [SQL Injection] (HIGH)"
        assert str(published_scenario) == expected

    def test_simulation_log_str(self, published_scenario, student_user):
        """Перевірка __str__ моделі SimulationLog."""
        log = SimulationLog.objects.create(
            scenario=published_scenario,
            executed_by=student_user,
            payload="' OR 1=1 --",
            defense_enabled=True,
            status=SimulationLog.SimulationStatus.MITIGATED,
            result_details="Атаку заблоковано.",
        )
        assert f"Симуляція #{log.pk} ({published_scenario.title}) - MITIGATED" == str(log)

