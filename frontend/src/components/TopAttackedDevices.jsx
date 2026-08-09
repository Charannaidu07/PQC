function TopAttackedDevices({
  devices
}) {

  return (

    <table
      className="
      table
      table-striped
      "
    >

      <thead>

        <tr>

          <th>
            Device
          </th>

          <th>
            Threats
          </th>

        </tr>

      </thead>

      <tbody>

        {devices.map(
          device => (

          <tr
            key={
              device.device_id
            }
          >

            <td>
              {
                device.device_id
              }
            </td>

            <td>
              {
                device.threats
              }
            </td>

          </tr>

        ))}

      </tbody>

    </table>
  );
}

export default TopAttackedDevices;