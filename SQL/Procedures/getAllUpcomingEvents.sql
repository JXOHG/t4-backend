DELIMITER $$

CREATE PROCEDURE GetUpcomingEvents()
BEGIN
    SELECT * FROM Event WHERE event_date > NOW() ORDER BY event_date ASC;
END $$

DELIMITER ;