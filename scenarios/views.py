import logging
from django.db import models
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
)

from .models import AttackScenario, SimulationLog
from .serializers import (
    AttackScenarioSerializer,
    SimulationRequestSerializer,
    SimulationResponseSerializer,
    SimulationLogSerializer,
)
from .permissions import IsScenarioOwnerOrAdminOrReadOnly

logger = logging.getLogger('scenarios')


@extend_schema_view(
    list=extend_schema(
        summary="Отримати список сценаріїв атак",
        description=(
            "Повертає список сценаріїв атак залежно від прав доступу:\n"
            "- **Гість (неавтентифікований)**: лише опубліковані сценарії (`is_published=true`).\n"
            "- **Студент/Користувач**: усі опубліковані + власні чернетки.\n"
            "- **Адміністратор**: усі сценарії системи (включно з неопублікованими чернетками всіх авторів).\n\n"
            "Підтримує фільтрацію за `vulnerability_type`, `severity` та пошук за ключовим словом `search`."
        ),
        tags=["Scenarios"],
        parameters=[
            OpenApiParameter(
                name="vulnerability_type",
                description="Фільтр за типом вразливості (SQLI, XSS, BAC, CSRF, SSRF)",
                required=False,
                type=str,
            ),
            OpenApiParameter(
                name="severity",
                description="Фільтр за рівнем критичності (LOW, MEDIUM, HIGH, CRITICAL)",
                required=False,
                type=str,
            ),
            OpenApiParameter(
                name="search",
                description="Пошук у назві або описі сценарію",
                required=False,
                type=str,
            ),
        ],
        responses={
            200: AttackScenarioSerializer(many=True),
        },
    ),
    retrieve=extend_schema(
        summary="Отримати деталі сценарію",
        description=(
            "Повертає повну інформацію про конкретний сценарій атаки.\n"
            "- Опубліковані сценарії доступні всім (включно з гостями).\n"
            "- Неопубліковані доступні лише їхньому автору або адміністратору."
        ),
        tags=["Scenarios"],
        responses={
            200: AttackScenarioSerializer,
            401: OpenApiResponse(description="Необхідна автентифікація для перегляду неопублікованого сценарію"),
            403: OpenApiResponse(description="Недостатньо прав для перегляду чужої чернетки"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
    ),
    create=extend_schema(
        summary="Створити новий сценарій атаки",
        description=(
            "Створює новий сценарій атаки. Потрібна автентифікація.\n"
            "- Звичайні користувачі створюють неопубліковані сценарії (`is_published=false`).\n"
            "- Тільки адміністратор має право встановлювати `is_published=true`."
        ),
        tags=["Scenarios"],
        request=AttackScenarioSerializer,
        responses={
            201: AttackScenarioSerializer,
            400: OpenApiResponse(description="Помилка валідації вхідних даних"),
            401: OpenApiResponse(description="Користувач не автентифікований"),
        },
        examples=[
            OpenApiExample(
                "Приклад створення SQL Injection сценарію",
                value={
                    "title": "SQL ін'єкція у формі авторизації",
                    "description": "Демонстрація обходу автентифікації через невалідований ввід логіна.",
                    "vulnerability_type": "SQLI",
                    "severity": "HIGH",
                    "attack_vector": "Введення ' OR '1'='1' у поле логіна для обходу перевірки пароля.",
                    "defense_mechanism": "Використання параметризованих запитів (Prepared Statements) та ORM.",
                    "defense_active": True,
                    "is_published": False,
                },
                request_only=True,
            ),
        ],
    ),
    update=extend_schema(
        summary="Повне оновлення сценарію (PUT)",
        description=(
            "Повне оновлення сценарію. Дозволено лише автору сценарію або адміністратору.\n"
            "Лише адміністратор може змінити статус `is_published` на `true`."
        ),
        tags=["Scenarios"],
        request=AttackScenarioSerializer,
        responses={
            200: AttackScenarioSerializer,
            400: OpenApiResponse(description="Некоректні дані"),
            401: OpenApiResponse(description="Не автентифіковано"),
            403: OpenApiResponse(description="Недостатньо прав (не є автором чи адміном)"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
    ),
    partial_update=extend_schema(
        summary="Часткове оновлення сценарію (PATCH)",
        description="Часткове оновлення полів сценарію. Дозволено автору або адміністратору.",
        tags=["Scenarios"],
        request=AttackScenarioSerializer,
        responses={
            200: AttackScenarioSerializer,
            400: OpenApiResponse(description="Некоректні дані"),
            401: OpenApiResponse(description="Не автентифіковано"),
            403: OpenApiResponse(description="Недостатньо прав"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
    ),
    destroy=extend_schema(
        summary="Видалити сценарій атаки",
        description="Видаляє сценарій атаки. Дозволено лише автору сценарію або адміністратору.",
        tags=["Scenarios"],
        responses={
            204: OpenApiResponse(description="Сценарій успішно видалено"),
            401: OpenApiResponse(description="Не автентифіковано"),
            403: OpenApiResponse(description="Недостатньо прав для видалення чужого сценарію"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
    ),
)
class AttackScenarioViewSet(viewsets.ModelViewSet):
    """
    CRUD ViewSet для управління сценаріями атак та запуску симуляцій.
    """
    queryset = AttackScenario.objects.all()
    serializer_class = AttackScenarioSerializer
    permission_classes = [IsScenarioOwnerOrAdminOrReadOnly]

    def get_queryset(self):
        user = self.request.user
        qs = AttackScenario.objects.select_related('created_by')

        # Управління видимістю за ролями
        if not user.is_authenticated:
            # Гість бачить лише публічні
            qs = qs.filter(is_published=True)
        elif not user.is_staff:
            # Студент бачить публічні та свої власні
            qs = qs.filter(models.Q(is_published=True) | models.Q(created_by=user))
        # Адміністратор бачить всі сценарії (qs без фільтрації прав)

        # Фільтрація за параметрами запиту
        vuln_type = self.request.query_params.get('vulnerability_type')
        if vuln_type:
            qs = qs.filter(vulnerability_type=vuln_type.upper())

        severity = self.request.query_params.get('severity')
        if severity:
            qs = qs.filter(severity=severity.upper())

        search = self.request.query_params.get('search')
        if search:
            qs = qs.filter(
                models.Q(title__icontains=search) |
                models.Q(description__icontains=search)
            )

        return qs

    def perform_create(self, serializer):
        user = self.request.user
        scenario = serializer.save(created_by=user)
        logger.info(
            "Користувач '%s' успішно створив новий сценарій атаки id=%s: '%s' (тип: %s, рівень: %s, опубліковано: %s)",
            user.username,
            scenario.pk,
            scenario.title,
            scenario.vulnerability_type,
            scenario.severity,
            scenario.is_published,
        )

    def perform_update(self, serializer):
        user = self.request.user
        scenario = serializer.save()
        logger.info(
            "Користувач '%s' оновив сценарій атаки id=%s: '%s'",
            user.username,
            scenario.pk,
            scenario.title,
        )

    def perform_destroy(self, instance):
        user = self.request.user
        scenario_id = instance.pk
        scenario_title = instance.title
        logger.info(
            "Користувач '%s' ініціював видалення сценарію атаки id=%s: '%s'",
            user.username,
            scenario_id,
            scenario_title,
        )
        instance.delete()
        logger.info("Сценарій атаки id=%s успішно видалено з бази даних.", scenario_id)

    @extend_schema(
        summary="Запуск симуляції атаки для сценарію",
        description=(
            "Запускає симуляцію вектора атаки з переданим корисним навантаженням (payload) "
            "та обраним станом захисного бар'єру (`defense_enabled`).\n"
            "- Якщо `defense_enabled=true`: захисний механізм блокує атаку (статус `MITIGATED`).\n"
            "- Якщо `defense_enabled=false`: атака проходить успішно (статус `BREACHED`).\n"
            "Потрібна автентифікація. Результат автоматично фіксується в журналі аудиту безпеки."
        ),
        tags=["Scenarios"],
        request=SimulationRequestSerializer,
        responses={
            200: SimulationResponseSerializer,
            400: OpenApiResponse(description="Некоректне корисне навантаження або параметри"),
            401: OpenApiResponse(description="Не автентифіковано"),
            403: OpenApiResponse(description="Немає доступу до симуляції даного сценарію"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
        examples=[
            OpenApiExample(
                "Симуляція з увімкненим захистом",
                value={"payload": "' OR 1=1 --", "defense_enabled": True},
                request_only=True,
            ),
            OpenApiExample(
                "Симуляція з вимкненим захистом",
                value={"payload": "<script>alert('XSS')</script>", "defense_enabled": False},
                request_only=True,
            ),
        ],
    )
    @action(
        detail=True,
        methods=['post'],
        permission_classes=[permissions.IsAuthenticated],
        url_path='simulate',
    )
    def simulate(self, request, pk=None):
        scenario = self.get_object()
        user = request.user

        logger.debug(
            "Користувач '%s' викликав endpoint симуляції для сценарію id=%s",
            user.username,
            scenario.pk,
        )

        serializer = SimulationRequestSerializer(data=request.data)
        if not serializer.is_valid():
            logger.warning(
                "Помилка валідації під час запуску симуляції для сценарію id=%s. Користувач: '%s', помилки: %s",
                scenario.pk,
                user.username,
                serializer.errors,
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        payload = serializer.validated_data['payload']
        defense_enabled = serializer.validated_data.get('defense_enabled', True)

        # Визначення результату симуляції
        if defense_enabled:
            sim_status = SimulationLog.SimulationStatus.MITIGATED
            is_blocked = True
            message = (
                f"Захисний механізм '{scenario.defense_mechanism}' успішно заблокував "
                f"атаку типу {scenario.get_vulnerability_type_display()}."
            )
            logger.info(
                "СИМУЛЯЦІЯ ЗАБЛОКОВАНА: Сценарій id=%s, тип=%s. "
                "Захист спрацював успішно для користувача '%s'.",
                scenario.pk,
                scenario.vulnerability_type,
                user.username,
            )
        else:
            sim_status = SimulationLog.SimulationStatus.BREACHED
            is_blocked = False
            message = (
                f"Увага! Захисний бар'єр вимкнено. Вектор атаки "
                f"{scenario.get_vulnerability_type_display()} успішно проникнув у систему!"
            )
            logger.warning(
                "СИМУЛЯЦІЯ ПРОРИВУ БЕЗПЕКИ: Сценарій id=%s, тип=%s. "
                "Бар'єр безпеки вимкнено користувачем '%s'!",
                scenario.pk,
                scenario.vulnerability_type,
                user.username,
            )

        # Безпечний запис у журнал: довжина payload, без відкриття чутливих паролів
        sim_log = SimulationLog.objects.create(
            scenario=scenario,
            executed_by=user,
            payload=payload[:200],  # обмежуємо розмір у базі даних
            defense_enabled=defense_enabled,
            status=sim_status,
            result_details=message,
        )

        response_data = {
            "simulation_id": sim_log.pk,
            "scenario_id": scenario.pk,
            "scenario_title": scenario.title,
            "vulnerability_type": scenario.vulnerability_type,
            "defense_enabled": defense_enabled,
            "is_blocked": is_blocked,
            "status": sim_status,
            "message": message,
            "created_at": sim_log.created_at,
        }

        return Response(response_data, status=status.HTTP_200_OK)

    @extend_schema(
        summary="Отримати журнал симуляцій для даного сценарію",
        description="Повертає історію запусків симуляцій для вказаного сценарію. Потрібна автентифікація.",
        tags=["Scenarios"],
        responses={
            200: SimulationLogSerializer(many=True),
            401: OpenApiResponse(description="Не автентифіковано"),
            403: OpenApiResponse(description="Недостатньо прав"),
            404: OpenApiResponse(description="Сценарій не знайдено"),
        },
    )
    @action(
        detail=True,
        methods=['get'],
        permission_classes=[permissions.IsAuthenticated],
        url_path='history',
    )
    def history(self, request, pk=None):
        scenario = self.get_object()
        logs = scenario.simulations.all().select_related('executed_by')
        serializer = SimulationLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
