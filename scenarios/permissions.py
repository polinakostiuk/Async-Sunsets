from rest_framework import permissions


class IsScenarioOwnerOrAdminOrReadOnly(permissions.BasePermission):
    """
    Дозволяє читання опублікованих сценаріїв усім користувачам (включаючи гостей).
    Неопубліковані (чернетки) можуть переглядати лише їхній автор та адміністратор.
    Редагування та видалення дозволено лише автору сценарію або адміністратору.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj):
        # Якщо сценарій опублікований - читання доступне всім
        if request.method in permissions.SAFE_METHODS:
            if obj.is_published:
                return True
            # Неопублікований сценарій доступний лише автору або адміну
            return bool(
                request.user and
                request.user.is_authenticated and
                (obj.created_by == request.user or request.user.is_staff)
            )

        # Зміна та видалення доступні тільки автору або адміністратору
        return bool(
            request.user and
            request.user.is_authenticated and
            (obj.created_by == request.user or request.user.is_staff)
        )
